package main

/*
	TODO tcp connection pooling
	TODO better logging format:
		 2018/04/21 21:39:02 123 172.16.21.245:55632 udp <=> 1.1.1.1:53 tcp-tls t.co A 123ms
	TODO cache
*/

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	"github.com/miekg/dns"
	"gopkg.in/tomb.v2"
	"gopkg.in/yaml.v2"
)

func main() {
	configPath := flag.String("conf", "quest.yml", "configuration file")
	flag.Parse()
	server, err := newServer(*configPath)
	if err != nil {
		fmt.Printf("err config: %s\n", err)
		os.Exit(1)
		return
	}
	log.SetFlags(log.LstdFlags)

	err = server.Serve()
	if err != nil {
		fmt.Printf("err serve: %s\n", err)
		os.Exit(2)
	}
}

type questServer struct {
	listens []struct {
		addr string
		net  string
	}
	cacheSize int
	resolvers map[string]questResolver
	routes    map[string]*questRouteTable

	t       tomb.Tomb
	servers []dns.Server
}

func newServer(configPath string) (server *questServer, err error) {
	config, err := readConfig(configPath)
	if err != nil {
		return
	}

	listens, err := validateListens(config.Server.Listens)
	if err != nil {
		return
	}

	resolvers, err := buildResolvers(config.Resolvers)
	if err != nil {
		return
	}

	routes, err := buildRoutes(config.Routes, resolvers)
	if err != nil {
		return
	}

	server = &questServer{
		listens:   listens,
		cacheSize: config.Server.CacheSize,
		resolvers: resolvers,
		routes:    routes,
	}

	return
}

func (s *questServer) Serve() error {
	startServer := func(l struct{ addr, net string }) {
		s.t.Go(func() error {
			server := dns.Server{Net: l.net, Addr: l.addr, Handler: s}
			errCh := make(chan error)
			go func() {
				log.Printf("serve on %s (%s)\n", l.addr, l.net)
				errCh <- server.ListenAndServe()
			}()

			select {
			case err := <-errCh:
				return err
			case <-s.t.Dying():
				return nil
			}
		})
	}

	for _, l := range s.listens {
		startServer(l)
	}
	return s.t.Wait()
}

func (s *questServer) Shutdown() error {
	s.t.Kill(nil)
	return s.t.Wait()
}

func (s *questServer) ServeDNS(w dns.ResponseWriter, r *dns.Msg) {
	if len(r.Question) == 0 {
		return
	}

	q := r.Question[0]

	go func() {
		for i := 0; i < 3; i++ {
			resp, err := s.resolve(r)
			if err != nil {
				log.Printf("[%05d] %s %s retring by %s\n",
					r.Id, q.Name, dns.Type(q.Qtype).String(), err)
				continue
			}
			err = w.WriteMsg(resp)
			if err != nil {
				log.Printf("[%05d] %s %s err respond: %s\n",
					r.Id, q.Name, dns.Type(q.Qtype).String(), err)
				return
			}
			break
		}
	}()
}

func (s *questServer) resolve(r *dns.Msg) (*dns.Msg, error) {
	q := r.Question[0]
	resolver, postActions := s.routes["main"].Route(q.Name)
	if resolver != nil {
		resp, err := resolver.Resolve(r)
		if err != nil {
			err := fmt.Errorf("err resolve: %s", err)
			return nil, err
		}
		if resp == nil {
			err := fmt.Errorf("err resolve: no respond")
			return nil, err
		}
		for _, action := range postActions {
			err := action.Do(resp)
			if err != nil {
				log.Printf("[%05d] %s %s err action: %#v %s\n",
					r.Id, q.Name, dns.Type(q.Qtype).String(), action, err)
			}
		}
		return resp, nil
	}
	err := fmt.Errorf("err route: could not found a suitable resolver")
	return nil, err
}

func buildResolvers(configs map[string]ConfigResolver) (resolvers map[string]questResolver, err error) {
	resolvers = make(map[string]questResolver)

	for name, config := range configs {
		resolverGroup := &questResolverGroup{name: name, resolvers: make([]*normalResolver, 0)}
		for _, rawServerConfig := range config.Server {
			serverConfig, ok := rawServerConfig.(map[interface{}]interface{})
			if !ok {
				if address, ok := rawServerConfig.(string); ok {
					serverConfig = make(map[interface{}]interface{})
					serverConfig["address"] = address
					serverConfig["mode"] = "udp"
				} else {
					err = fmt.Errorf("Invalid config: invalid resolver config at '%s'", name)
					return
				}
			}

			var r *normalResolver
			var address string
			if i, ok := serverConfig["address"]; !ok {
				err = fmt.Errorf("Invalid config: address are required at resolver '%s'", name)
				return
			} else if address, ok = i.(string); !ok {
				err = fmt.Errorf("Invalid config: address must be a string at resolver '%s'", name)
				return
			}
			mode := "udp"
			if i, ok := serverConfig["mode"]; ok {
				mode, _ = i.(string)
			}

			var client Client
			switch mode {
			case "tcp":
				address = withDefaultPort(address, "53")
				var addr *net.TCPAddr
				addr, err = net.ResolveTCPAddr("tcp", address)
				if err != nil {
					return
				}
				client = NewTCPClient(addr)
			case "udp":
				address = withDefaultPort(address, "53")
				var addr *net.UDPAddr
				addr, err = net.ResolveUDPAddr("udp", address)
				if err != nil {
					return
				}
				client = NewUDPClient(addr)
			case "dns-over-tls":
				address = withDefaultPort(address, "853")
				var hostname string
				if i, ok := serverConfig["hostname"]; !ok {
					err = fmt.Errorf("Invalid config: hostname are required at resolver '%s'", name)
					return
				} else if hostname, ok = i.(string); !ok {
					err = fmt.Errorf("Invalid config: hostname must be a string at resolver '%s'", name)
					return
				}
				tlsConfig := DefaultTLSConfig()
				tlsConfig.ServerName = hostname
				var addr *net.TCPAddr
				addr, err = net.ResolveTCPAddr("tcp", address)
				if err != nil {
					return
				}
				client = NewTLSClient(addr, tlsConfig)
			default:
				err = fmt.Errorf("Invalid config: invalid mode at resolver '%s'", name)
				return
			}

			r = &normalResolver{client: client, address: address}
			resolverGroup.resolvers = append(resolverGroup.resolvers, r)
		}
		resolvers[name] = resolverGroup
	}
	return
}

type normalResolver struct {
	client  Client
	address string
}

func (r *normalResolver) Resolve(msg *dns.Msg) (*dns.Msg, time.Duration, error) {
	return r.client.Exchange(msg)
}

type questResolverGroup struct {
	name      string
	resolvers []*normalResolver
}

func (r *questResolverGroup) Resolve(msg *dns.Msg) (*dns.Msg, error) {
	type Result struct {
		resolver *normalResolver
		msg      *dns.Msg
		rtt      time.Duration
		err      error
	}
	results := make(chan Result)
	defer close(results)

	for _, r := range r.resolvers {
		go func(r *normalResolver) {
			rmsg, rtt, err := r.Resolve(msg)
			func() {
				defer func() { recover() }()
				results <- Result{r, rmsg, rtt, err}
			}()
		}(r)
	}
	var result Result
	for i := len(r.resolvers); i != 0; i-- {
		result = <-results
		if result.err == nil {
			break
		}
	}
	question := msg.Question[0]
	resolver := result.resolver
	log.Printf(
		"[%05d] %s %s -> %s(%s) %s\n",
		msg.Id,
		question.Name,
		dns.Type(question.Qtype).String(),
		resolver.client.Addr(),
		resolver.client.Net(),
		result.rtt.Round(time.Millisecond),
	)
	return result.msg, result.err
}

type questResolver interface {
	Resolve(*dns.Msg) (*dns.Msg, error)
}

func buildRoutes(routesConfig map[string][]ConfigRoute, resolvers map[string]questResolver) (routes map[string]*questRouteTable, err error) {
	routes = make(map[string]*questRouteTable)
	for name := range routesConfig {
		routes[name] = &questRouteTable{routes: make([]*questRoute, 0), name: name}
	}
	for name, routesDef := range routesConfig {
		t := routes[name]

		for _, routeDef := range routesDef {
			r := &questRoute{rule: &questRuleAny{}}
			for instruction, param := range routeDef {
				switch strings.ToUpper(instruction) {
				case "DOMAIN-SUFFIX":
					r.rule = &questRuleDomainSuffix{suffix: fmt.Sprintf("%s.", param)}
				case "ROUTE":
					if r.resolver != nil {
						err = fmt.Errorf("Invalid config: connot use ROUTE and RESOLVER at same route")
						return
					}
					if param == name {
						err = fmt.Errorf("Invalid config: cyclic routing in route table '%s'", name)
					}
					if table, ok := routes[param]; ok {
						r.table = table
					} else {
						err = fmt.Errorf("Invalid config: unknown route table '%s'", param)
						return
					}
				case "RESOLVER":
					if r.table != nil {
						err = fmt.Errorf("Invalid config: connot use ROUTE and RESOLVER at same route")
						return
					}
					if resolver, ok := resolvers[param]; ok {
						r.resolver = resolver
					} else {
						err = fmt.Errorf("Invalid config: unknown resolver '%s'", param)
						return
					}
				case "IPSET":
					r.postAction = &ipsetAction{setName: param}
				}
			}
			t.routes = append(t.routes, r)
		}
	}

	if _, ok := routes["main"]; !ok {
		err = fmt.Errorf("Invalid config: 'main' route are required")
		return
	}
	return
}

type questPostAction interface {
	Do(msg *dns.Msg) error
}

type ipsetAction struct {
	setName string
}

func (a *ipsetAction) Do(msg *dns.Msg) error {
	for _, answer := range msg.Answer {
		var ip string
		switch rr := answer.(type) {
		case *dns.A:
			ip = rr.A.String()
		case *dns.AAAA:
			ip = rr.AAAA.String()
		default:
			continue
		}
		cmd := exec.Command("ipset", "add", a.setName, ip)
		out, err := cmd.CombinedOutput()
		if err != nil {
			if bytes.Contains(out, []byte("already added")) {
				return nil
			}
			err = fmt.Errorf("ipset %s: %s", err, out)
			return err
		}
	}
	return nil
}

type questRouteTable struct {
	name   string
	routes []*questRoute
}

func (r *questRouteTable) Route(domain string) (resolver questResolver, cumulatedPostActions []questPostAction) {
	cumulatedPostActions = make([]questPostAction, 0)
	for _, route := range r.routes {
		var postActions []questPostAction
		resolver, postActions = route.Route(domain)
		cumulatedPostActions = append(cumulatedPostActions, postActions...)
		if resolver != nil {
			return
		}
	}
	return
}

type questRoute struct {
	rule       questRule
	table      *questRouteTable
	postAction questPostAction
	resolver   questResolver
}

func (r *questRoute) Route(domain string) (resolver questResolver, cumulatedPostActions []questPostAction) {
	cumulatedPostActions = make([]questPostAction, 0)
	if r.rule.Match(domain) {
		if r.postAction != nil {
			cumulatedPostActions = append(cumulatedPostActions, r.postAction)
		}
		if r.table != nil {
			var postActions []questPostAction
			resolver, postActions = r.table.Route(domain)
			cumulatedPostActions = append(cumulatedPostActions, postActions...)
			return
		}
		if r.resolver != nil {
			resolver = r.resolver
			return
		}
	}
	return
}

type questRule interface {
	Match(domain string) bool
}

type questRuleDomainSuffix struct {
	suffix string
}

func (r *questRuleDomainSuffix) Match(domain string) bool {
	ok := strings.HasSuffix(strings.ToLower(domain), strings.ToLower(r.suffix))
	return ok
}

type questRuleAny struct{}

func (r *questRuleAny) Match(domain string) bool { return true }

// Config config struct
type Config struct {
	Server    ConfigServer              `yaml:"server"`
	Resolvers map[string]ConfigResolver `yaml:"resolvers"`
	Routes    map[string][]ConfigRoute  `yaml:"routes"`
}

// ConfigRoute config struct
type ConfigRoute map[string]string

// ConfigServer config struct
type ConfigServer struct {
	Listens   []map[string]string `yaml:"listens"`
	CacheSize int                 `yaml:"cache_size"`
}

// ConfigResolver config struct
type ConfigResolver struct {
	Server []interface{} `yaml:"server"`
}

func readConfig(configPath string) (config *Config, err error) {
	config = &Config{
		Server: ConfigServer{
			Listens:   make([]map[string]string, 0),
			CacheSize: 1000,
		},
		Resolvers: make(map[string]ConfigResolver),
		Routes:    make(map[string][]ConfigRoute),
	}

	var configData []byte
	configData, err = ioutil.ReadFile(configPath)
	if err != nil {
		return
	}

	err = yaml.Unmarshal(configData, config)
	if err != nil {
		err = fmt.Errorf("Invalid config: %s", err)
		return
	}
	return
}

func validateListens(listens []map[string]string) (out []struct{ addr, net string }, err error) {
	out = make([]struct{ addr, net string }, 0, len(listens))
	for i, l := range listens {
		var proto, addr string
		for proto, addr = range l {
			proto = strings.ToLower(proto)
			switch proto {
			case "tcp", "udp":
			default:
				err = fmt.Errorf("Invalid config: invalid protocol in server.listen[%d], tcp or udp are expected", i)
				return
			}
			addr = withDefaultPort(addr, "53")
			_, err = net.ResolveUDPAddr("udp", addr)
			if err != nil {
				err = fmt.Errorf("Invalid config: invalid address in server.listen[%d], %s", i, err)
				return
			}
			break
		}

		out = append(out, struct{ addr, net string }{addr, proto})
	}
	return
}

func withDefaultPort(address, defaultPort string) string {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		host, port = address, defaultPort
	}
	return net.JoinHostPort(host, port)
}

// DefaultTLSConfig default tls config
func DefaultTLSConfig() *tls.Config {
	roots, err := x509.SystemCertPool()
	if err != nil {
		panic("Cannot get system CAs")
	}
	return &tls.Config{RootCAs: roots}
}
