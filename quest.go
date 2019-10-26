package main

/*
	TODO resolver configuration (pooling, retry, timeout etc.)
	TODO respond ahead of query
*/

import (
	"bytes"
	"context"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"strings"
	"time"

	tomb "gopkg.in/tomb.v2"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/go-yaml/yaml"
	"github.com/miekg/dns"
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
	namedUpstreams map[string][]upstream.Upstream
	routes         map[string]*questRouteTable

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

	namedUpstreams, err := buildUpstreams(config.Resolvers)
	if err != nil {
		return
	}

	routes, err := buildRoutes(config.Routes, namedUpstreams)
	if err != nil {
		return
	}

	server = &questServer{
		listens:        listens,
		namedUpstreams: namedUpstreams,
		routes:         routes,
	}

	return
}

func (s *questServer) loaderExpireFunc(key interface{}) (interface{}, *time.Duration, error) {
	// q := key.(dns.Question)
	// result, err := s.query(q)
	// if err != nil {
	// 	return nil, nil, err
	// }
	// var ttl time.Duration
	// if len(result.msg.Answer) == 0 {
	// 	ttl = 5 * time.Second
	// } else {
	// 	a := result.msg.Answer[0]
	// 	ttl = time.Duration(a.Header().Ttl) * time.Second
	// 	for _, a = range result.msg.Answer {
	// 		if a.Header().Rrtype == q.Qtype {
	// 			ttl = time.Duration(a.Header().Ttl) * time.Second
	// 			break
	// 		}
	// 	}
	// }
	// return result, &ttl, nil
	panic("1")
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

func (s *questServer) ServeDNS(w dns.ResponseWriter, m *dns.Msg) {
	if len(m.Question) == 0 {
		log.Printf("[%05d] empty query", m.Id)
		return
	}

	start := time.Now()
	q := m.Question[0]
	result, err := s.query(q)

	var r *dns.Msg
	if err != nil {
		log.Printf("[%05d] %s %s query err %s", m.Id, q.Name, dns.Type(q.Qtype).String(), err)
		r = m.Copy()
		r.MsgHdr.Rcode = dns.RcodeServerFailure
	} else {
		r = result.resp.Copy()
		r.Id = m.Id

		question := m.Question[0]
		rtt := time.Now().Sub(start)
		log.Printf(
			"[%05d] %s %s %s -> %s %s\n",
			m.Id,
			question.Name,
			dns.Type(question.Qtype).String(),
			w.RemoteAddr(),
			result.u.Address(),
			rtt.Round(time.Millisecond),
		)
	}

	err = w.WriteMsg(r)
	if err != nil {
		log.Printf("[%05d] %s %s respond err %s", m.Id, q.Name, dns.Type(q.Qtype).String(), err)
	}
}

func (s *questServer) query(q dns.Question) (*queryResult, error) {
	ctx := context.Background()

	upstreams, postActions := s.routes["main"].Route(q.Name)
	if upstreams == nil {
		err := fmt.Errorf("could not found a sutable resolver for this query")
		return nil, err
	}
	m := &dns.Msg{}
	m.Id = dns.Id()
	m.Question = []dns.Question{q}
	m.RecursionDesired = true

	rc := make(chan *queryResult, 1)

	go func() {
		msgCopy := m.Copy()
		msgCopy.Id = dns.Id()
		start := time.Now()
		resp, u, err := upstream.ExchangeParallel(upstreams, msgCopy)
		if ctx.Err() != nil {
			return
		}
		rc <- &queryResult{
			resp: resp,
			err:  err,
			u:    u,
			rtt:  time.Since(start),
		}
	}()

	var r *queryResult
	select {
	case r = <-rc:
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	if r.err != nil {
		return nil, r.err
	}

	resp := r.resp.Copy()
	resp.Id = m.Id

	for _, a := range postActions {
		err := a.Do(resp)
		if err != nil {
			log.Printf("[%05d] failed to do action %T: %s\n", resp.Id, a, err)
		}
	}

	return r, nil
}

func buildUpstreams(configs map[string]ConfigResolver) (namedResolvers map[string][]upstream.Upstream, err error) {
	namedResolvers = make(map[string][]upstream.Upstream)

	for name, config := range configs {
		upstreams := make([]upstream.Upstream, 0)
		for _, addr := range config.Server {
			u, err := upstream.AddressToUpstream(addr, upstream.Options{Timeout: 120 * time.Second})
			if err != nil {
				panic(err)
			}
			upstreams = append(upstreams, u)
		}
		namedResolvers[name] = upstreams
	}
	return
}

func parseTimeout(config map[interface{}]interface{}, name string) (dur time.Duration, err error) {
	dur = 5 * time.Second
	if i, ok := config["timeout"]; ok {
		s, ok := i.(string)
		if !ok {
			err = fmt.Errorf("Invalid config: timeout must be a string at resolver '%s'", name)
			return
		}
		dur, err = time.ParseDuration(s)
		if err != nil {
			err = fmt.Errorf("Invalid config: unknown timeout format (hints: 15s, 1m) at resolver '%s'", name)
			return
		}
	}
	return
}

func buildRoutes(routesConfig map[string][]ConfigRoute, namedResolvers map[string][]upstream.Upstream) (routes map[string]*questRouteTable, err error) {
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
					if r.upstreams != nil {
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
					if upstreams, ok := namedResolvers[param]; ok {
						r.upstreams = upstreams
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
		err := a.ipsetAdd(ip)
		if err != nil {
			return err
		}
	}
	return nil
}

func (a *ipsetAction) ipsetAdd(ip string) error {
	cmd := exec.Command("ipset", "add", a.setName, ip)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if bytes.Contains(out, []byte("already added")) {
			return nil
		}
		err = fmt.Errorf("ipset %s: %s", err, out)
		return err
	}
	return nil
}

type questRouteTable struct {
	name   string
	routes []*questRoute
}

func (r *questRouteTable) Route(domain string) (upstreams []upstream.Upstream, cumulatedPostActions []questPostAction) {
	cumulatedPostActions = make([]questPostAction, 0)
	for _, route := range r.routes {
		var postActions []questPostAction
		upstreams, postActions = route.Route(domain)
		cumulatedPostActions = append(cumulatedPostActions, postActions...)
		if upstreams != nil {
			return
		}
	}
	return
}

type questRoute struct {
	rule       questRule
	table      *questRouteTable
	postAction questPostAction
	upstreams  []upstream.Upstream
}

func (r *questRoute) Route(domain string) (upstreams []upstream.Upstream, cumulatedPostActions []questPostAction) {
	cumulatedPostActions = make([]questPostAction, 0)
	if r.rule.Match(domain) {
		if r.postAction != nil {
			cumulatedPostActions = append(cumulatedPostActions, r.postAction)
		}
		if r.table != nil {
			var postActions []questPostAction
			upstreams, postActions = r.table.Route(domain)
			cumulatedPostActions = append(cumulatedPostActions, postActions...)
			return
		}
		if r.upstreams != nil {
			upstreams = r.upstreams
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
	Listens []map[string]string `yaml:"listens"`
}

// ConfigResolver config struct
type ConfigResolver struct {
	Server []string `yaml:"server"`
}

func readConfig(configPath string) (config *Config, err error) {
	config = &Config{
		Server: ConfigServer{
			Listens: make([]map[string]string, 0),
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

type queryResult struct {
	resp *dns.Msg
	err  error
	u    upstream.Upstream
	rtt  time.Duration
}
