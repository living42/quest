package main

import (
	"container/list"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolver
type Resolver struct {
	address string
	client  *dns.Client
	pool    *connectionPool
	connsMu sync.Mutex
	config  *ResolverConfig
}

// ResolverConfig config
type ResolverConfig struct {
	maxIdleConn   int
	maxRetryCount int
}

// DefaultResolverConfig default config
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		maxIdleConn:   5,
		maxRetryCount: 5,
	}
}

func newResolver(address string, c *dns.Client, config *ResolverConfig) *Resolver {
	if config == nil {
		config = DefaultResolverConfig()
	}
	return &Resolver{
		address: address,
		client:  c,
		config:  config,
		pool: &connectionPool{
			address:     address,
			c:           c,
			idle:        list.New(),
			active:      make(map[int]*Conn),
			maxIdleConn: config.maxIdleConn,
		},
	}
}

// Resolve resolver
func (c *Resolver) Resolve(m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	start := time.Now()
	defer func() {
		rtt = time.Now().Sub(start)
	}()

	for i := 0; i < c.config.maxRetryCount; i++ {
		var conn *Conn
		conn, err = c.pool.Get()
		if err != nil {
			continue
		}
		err = conn.WriteMsg(m)
		if err != nil {
			continue
		}
		r, err = conn.ReadMsg()
		if err != nil {
			continue
		}
		c.pool.Add(conn)
		return
	}
	return
}

type connectionPool struct {
	counter     int
	address     string
	c           *dns.Client
	idle        *list.List
	active      map[int]*Conn
	maxIdleConn int
	mu          sync.Mutex
}

// Conn conn
type Conn struct {
	*dns.Conn
	id      int
	created time.Time
}

func (p *connectionPool) Get() (c *Conn, err error) {
	c = p.getIdleConn()
	if c != nil {
		return
	}
	p.counter++
	id := p.counter
	dnsConn, err := p.c.Dial(p.address)
	c = &Conn{Conn: dnsConn, id: id, created: time.Now()}
	if err != nil {
		return
	}
	p.mu.Lock()
	p.active[id] = c
	p.mu.Unlock()
	return
}

func (p *connectionPool) getIdleConn() (c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()

	for p.idle.Len() > 0 {
		e := p.idle.Front()
		p.idle.Remove(e)
		c = e.Value.(*Conn)
		if now.Sub(c.created) > 10*time.Second {
			c.Close()
			continue
		}
		p.active[c.id] = c
		return
	}
	return
}

func (p *connectionPool) Add(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if _, ok := p.active[c.id]; ok {
		delete(p.active, c.id)
		if p.idle.Len() < p.maxIdleConn {
			p.idle.PushBack(c)
		} else {
			c.Close()
		}
	}
}
