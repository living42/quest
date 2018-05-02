package main

import (
	"crypto/tls"
	"net"
	"time"

	"github.com/miekg/dns"
)

// Client client interface
type Client interface {
	Exchange(req *dns.Msg) (resp *dns.Msg, rtt time.Duration, err error)
	Addr() net.Addr
	Net() string
}

// BaseClient base client
type BaseClient struct {
	address net.Addr
	net     string
}

// Addr address of remove server
func (c *BaseClient) Addr() net.Addr {
	return c.address
}

// Net proto of transport
func (c *BaseClient) Net() string {
	return c.net
}

// UDPClient UDP client
type UDPClient struct {
	BaseClient
	client *dns.Client
}

// NewUDPClient initialize UDPClient
func NewUDPClient(addr *net.UDPAddr) *UDPClient {
	return &UDPClient{
		client: &dns.Client{Net: "udp"},
		BaseClient: BaseClient{
			net:     "udp",
			address: addr,
		},
	}
}

// Exchange exchange message
func (c *UDPClient) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	return c.client.Exchange(req, c.address.String())
}

// TCPClient TCP client
type TCPClient struct {
	BaseClient
	client *dns.Client
}

// NewTCPClient initialize TCPClient
func NewTCPClient(addr *net.TCPAddr) *TCPClient {
	return &TCPClient{
		client: &dns.Client{Net: "tcp"},
		BaseClient: BaseClient{
			address: addr,
			net:     "tcp",
		},
	}
}

// Exchange exchange message
func (c *TCPClient) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	return c.client.Exchange(req, c.address.String())
}

// TLSClient TCP client
type TLSClient struct {
	BaseClient
	client *dns.Client
}

// NewTLSClient initialize TLSClient
func NewTLSClient(addr *net.TCPAddr, tlsConfig *tls.Config) *TLSClient {
	return &TLSClient{
		client: &dns.Client{Net: "tcp-tls", TLSConfig: tlsConfig},
		BaseClient: BaseClient{
			address: addr,
			net:     "tcp-tls",
		},
	}
}

// Exchange exchange message
func (c *TLSClient) Exchange(req *dns.Msg) (*dns.Msg, time.Duration, error) {
	return c.client.Exchange(req, c.address.String())
}
