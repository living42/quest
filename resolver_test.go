package main

import (
	"testing"
	"time"

	"github.com/miekg/dns"
)

func testResolve(resolver *Resolver, t *testing.T) {
	for i := 0; i < 10; i++ {

		for j := 0; j < 3; j++ {
			go func() {

				m := &dns.Msg{}
				m.SetQuestion("t.co.", dns.TypeA)
				m.Id = dns.Id()
				_, rtt, err := resolver.Resolve(m)
				t.Logf(
					"after: rtt: %s idle: %d active: %d\n",
					rtt.Round(time.Millisecond), resolver.pool.idle.Len(), len(resolver.pool.active),
				)
				if err != nil {
					t.Error(err)
				}
			}()
		}
		time.Sleep(500 * time.Millisecond)

	}
}

func TestResolveViaTLS(t *testing.T) {
	c := &dns.Client{Net: "tcp-tls", TLSConfig: DefaultTLSConfig()}
	resolver := newResolver("1.1.1.1:853", c, nil)
	testResolve(resolver, t)
}

func TestResolveViaUDP(t *testing.T) {
	c := &dns.Client{Net: "udp"}
	resolver := newResolver("1.1.1.1:53", c, nil)
	testResolve(resolver, t)
}

func TestResolveViaTCP(t *testing.T) {
	c := &dns.Client{Net: "tcp"}
	resolver := newResolver("1.1.1.1:53", c, nil)
	testResolve(resolver, t)
}