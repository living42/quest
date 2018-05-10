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
	maxIdleTime   time.Duration
}

// DefaultResolverConfig default config
func DefaultResolverConfig() *ResolverConfig {
	return &ResolverConfig{
		maxIdleConn:   5,
		maxRetryCount: 5,
		maxIdleTime:   10 * time.Second,
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
			maxIdleConn: config.maxIdleConn,
			maxIdleTime: config.maxIdleTime,
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
			conn.Close()
			continue
		}
		r, err = conn.ReadMsg()
		if err != nil {
			conn.Close()
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
	maxIdleConn int
	maxIdleTime time.Duration
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
	return
}

func (p *connectionPool) getIdleConn() *Conn {
	p.mu.Lock()
	defer p.mu.Unlock()
	now := time.Now()

	for p.idle.Len() > 0 {
		e := p.idle.Front()
		p.idle.Remove(e)
		c := e.Value.(*Conn)
		if now.Sub(c.created) > p.maxIdleTime {
			c.Close()
			continue
		}
		return c
	}
	return nil
}

func (p *connectionPool) Add(c *Conn) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.idle.Len() < p.maxIdleConn {
		p.idle.PushBack(c)
	} else {
		c.Close()
	}
}
