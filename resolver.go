package main

import (
	"context"
	"log"
	"net"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// Resolver resolver
type Resolver struct {
	address string
	client  *dns.Client
	connsMu sync.Mutex
	config  ResolverConfig
	idles   []*conn
	idleMu  sync.Mutex
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
		maxIdleConn:   2,
		maxRetryCount: 5,
		maxIdleTime:   30 * time.Second,
	}
}

func newResolver(address string, c *dns.Client, config *ResolverConfig) *Resolver {
	if config == nil {
		config = DefaultResolverConfig()
	}
	return &Resolver{
		address: address,
		client:  c,
		config:  *config,
		idles:   make([]*conn, 0),
	}
}

// Resolve resolver
func (c *Resolver) Resolve(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error) {
	start := time.Now()
	defer func() { rtt = time.Now().Sub(start) }()

	co, err := c.getConn()
	if err != nil {
		return
	}
	log.Printf("open %s - %s\n", co.LocalAddr(), co.RemoteAddr())
	err = co.writeReq(m)
	if err != nil {
		return
	}

	select {
	case <-ctx.Done():
		r = nil
		err = ctx.Err()
		return
	case res := <-co.resCh:
		r = res.r
		err = res.err
		return
	}
}

func (c *Resolver) getConn() (*conn, error) {
	co := c.getIdleConn()
	if co != nil {
		log.Printf("use idle conn %s - %s\n", co.LocalAddr(), co.RemoteAddr())
		return co, nil
	}

	dc, err := c.client.Dial(c.address)
	if err != nil {
		return nil, err
	}
	co = &conn{Conn: dc, resCh: make(chan *result), r: c}
	go co.readloop()
	return co, nil
}

func (c *Resolver) getIdleConn() *conn {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if len(c.idles) > 0 {
		co := c.idles[0]
		c.idles = c.idles[1:]
		return co
	}
	return nil
}

type conn struct {
	*dns.Conn
	resCh chan *result
	r     *Resolver
}

type result struct {
	r   *dns.Msg
	err error
}

func (c *conn) writeReq(m *dns.Msg) error {
	err := c.WriteMsg(m)
	if err != nil {
		return err
	}
	c.SetReadDeadline(time.Now().Add(15 * time.Second))
	return nil
}

func (c *conn) readloop() {
	defer func() {
		c.Close()
		close(c.resCh)
		c.r.removeIdle(c)
		log.Printf("close %s - %s\n", c.LocalAddr(), c.RemoteAddr())
	}()

	start := time.Now()

	for {
		c.SetReadDeadline(time.Now().Add(15 * time.Second))
		r, err := c.ReadMsg()
		c.SetReadDeadline(time.Time{})
		select {
		case c.resCh <- &result{r: r, err: err}:
		default:
		}
		if err != nil {
			if netErr, ok := err.(*net.OpError); !ok || netErr.Timeout() {
				return
			}
		}
		if time.Now().Sub(start) > c.r.config.maxIdleTime {
			return
		}
		if !c.r.putIdle(c) {
			return
		}
		log.Printf("put idle conn %s - %s\n", c.LocalAddr(), c.RemoteAddr())
	}
}

func (c *Resolver) putIdle(co *conn) bool {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	if len(c.idles) >= c.config.maxIdleConn {
		return false
	}
	c.idles = append(c.idles, co)
	return true
}

func (c *Resolver) removeIdle(co *conn) bool {
	c.idleMu.Lock()
	defer c.idleMu.Unlock()
	switch len(c.idles) {
	case 0:
		return false
	case 1:
		if c.idles[0] == co {
			c.idles = c.idles[1:]
			return true
		}
	default:
		for i, v := range c.idles {
			if v != co {
				continue
			}
			c.idles = append(c.idles[:i], c.idles[i+1:]...)
			return true
		}
	}
	return false
}
