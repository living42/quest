package main

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/tomb.v2"
)

// Resolver resolver interface
type Resolver interface {
	Resolve(ctx context.Context, m *dns.Msg) (r *dns.Msg, rtt time.Duration, err error)
	Server() string
}

type resolver2Msg struct {
	m    *dns.Msg
	rmsg *dns.Msg
	err  error
	done chan struct{}
}

func (r *resolver2Msg) markAsDone() {
	select {
	case <-r.done:
	default:
		close(r.done)
	}
}

type resolver2Conn struct {
	tomb       tomb.Tomb
	conn       *dns.Conn
	flyingMsgs map[uint16]*resolver2Msg
}

func newResolver2Conn(client *dns.Client, address string) (*resolver2Conn, error) {
	r := resolver2Conn{
		flyingMsgs: make(map[uint16]*resolver2Msg),
	}

	log.Printf("dial to %s://%s\n", client.Net, address)
	conn, err := client.Dial(address)
	if err != nil {
		return nil, err
	}

	r.conn = conn

	r.tomb.Go(r.readLoop)

	r.tomb.Go(func() error {
		<-r.tomb.Dying()
		log.Printf("diying %s://%s", client.Net, address)
		return nil
	})

	return &r, nil
}

func (r *resolver2Conn) writeMsg(msg *resolver2Msg) error {
	err := r.conn.WriteMsg(msg.m)
	if err != nil {
		return err
	}
	r.flyingMsgs[msg.m.Id] = msg
	return nil
}

func (r *resolver2Conn) readLoop() error {
	defer r.conn.Close()

	conn := r.conn

	for {
		rmsg, err := conn.ReadMsg()

		if err != nil {
			for _, msg := range r.flyingMsgs {
				msg.err = err
				msg.markAsDone()
			}
			return err
		}

		if msg, ok := r.flyingMsgs[rmsg.Id]; ok {
			msg.rmsg = rmsg
			msg.err = err
			msg.markAsDone()
			delete(r.flyingMsgs, rmsg.Id)
		}

	}
}

func (r *resolver2Conn) Dying() <-chan struct{} {
	return r.tomb.Dying()
}

type resolver2 struct {
	client  *dns.Client
	address string
	msgCh   chan *resolver2Msg
}

func newResolver2(address string, c *dns.Client, config *ResolverConfig) *resolver2 {
	r := resolver2{
		client:  c,
		address: address,
		msgCh:   make(chan *resolver2Msg),
	}

	go r.scheduler()

	return &r
}

func (r *resolver2) scheduler() {
	msgChIn := r.msgCh

	var conn *resolver2Conn
	var err error

	for msg := range msgChIn {
		err = nil

		if conn == nil {
			conn, err = newResolver2Conn(r.client, r.address)
		} else {
			select {
			case <-conn.Dying():
				conn, err = newResolver2Conn(r.client, r.address)
			default:
			}
		}

		if err != nil {
			msg.err = err
			msg.markAsDone()
		} else {
			err = conn.writeMsg(msg)
			if err != nil {
				msg.err = err
				msg.markAsDone()
			}
		}
	}
}

func (r *resolver2) Server() string {
	return fmt.Sprintf("%s://%s", r.client.Net, r.address)
}

func (r *resolver2) Resolve(ctx context.Context, m *dns.Msg) (rmsg *dns.Msg, rtt time.Duration, err error) {
	msg := resolver2Msg{
		m:    m,
		done: make(chan struct{}),
	}
	r.msgCh <- &msg
	select {
	case <-msg.done:
		rmsg = msg.rmsg
		err = msg.err
		return
	case <-ctx.Done():
		err = ctx.Err()
		return
	}
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
