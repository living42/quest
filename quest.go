package main

import (
	"bytes"
	"container/list"
	"errors"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AdguardTeam/dnsproxy/upstream"
	"github.com/go-yaml/yaml"
	"github.com/miekg/dns"
)

func main() {
	confPath := flag.String("conf", "quest.yml", "configuration file")
	flag.Parse()

	conf, err := loadConfig(*confPath)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
		return
	}

	quest := Quest{conf: conf, cache: NewCache(conf.Server.CacheSize)}
	err = quest.Run()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

type Quest struct {
	conf      Config
	upstreams map[string]func() ([]upstream.Upstream, error)
	cache     *Cache
}

func msgKey(msg *dns.Msg) string {
	q := msg.Question[0]
	return q.String()
}

var errNotRuleMatch = fmt.Errorf("not rule match with")

func (q *Quest) ServeDNS(w dns.ResponseWriter, req *dns.Msg) {
	start := time.Now()
	domain := req.Question[0].Name
	resp, u, cached, err := q.cache.GetOrCreate(req, func() (*dns.Msg, upstream.Upstream, error) {
		rule, ok := q.findRule(domain)
		if !ok {
			log.Printf("W %s %s not rule match with\n", w.RemoteAddr(), req.Question[0].Name)
			req.MsgHdr.Rcode = dns.RcodeServerFailure
			w.WriteMsg(req)
			return req, nil, errNotRuleMatch
		}
		allUpstreams := []upstream.Upstream{}
		for _, addr := range rule.Resolvers {
			upstreams, err := q.upstreams[addr]()
			if err != nil {
				return req, nil, err
			}
			for _, u := range upstreams {
				log.Printf("D %s %s -> %s\n", w.RemoteAddr(), domain, u.Address())
				allUpstreams = append(allUpstreams, u)
			}
		}
		resp, u, err := upstream.ExchangeParallel(allUpstreams, req)
		if err != nil {
			log.Printf("E %s %s %s\n", w.RemoteAddr(), domain, err)
			resp = req.Copy()
			resp.Rcode = dns.RcodeServerFailure
		} else {
			if rule.IPSet != "" && hasIPSetCmd() {
				for _, rr := range resp.Answer {
					var ip string
					switch rr := rr.(type) {
					case *dns.A:
						ip = rr.A.String()
					case *dns.AAAA:
						ip = rr.AAAA.String()
					default:
						continue
					}
					log.Printf("D %s %s +ipset add %s %s\n", w.RemoteAddr(), domain, rule.IPSet, ip)
					err := ipsetAdd(rule.IPSet, ip)
					if err != nil {
						log.Printf("E %s %s ipset add: %s\n", w.RemoteAddr(), domain, err)
					}
				}
			}
		}
		return resp, u, err
	})
	duration := time.Now().Sub(start).Round(time.Millisecond)
	if err == nil {
		if cached {
			log.Printf("I %s %s <- %s %s (cached)\n", w.RemoteAddr(), domain, u.Address(), duration)
		} else {
			log.Printf("I %s %s <- %s %s\n", w.RemoteAddr(), domain, u.Address(), duration)
		}
	}
	w.WriteMsg(resp)
}

func (q *Quest) findRule(domain string) (Rule, bool) {
	for _, rule := range q.conf.Rules {
		if len(rule.DomainSuffix) == 0 {
			return rule, true
		}
		for _, suffix := range rule.DomainSuffix {
			if strings.HasSuffix(domain, suffix) {
				return rule, true
			}
		}
	}
	return Rule{}, false
}

func (q *Quest) Run() error {
	log.Printf("I cahe size is %d\n", q.conf.Server.CacheSize)
	q.upstreams = make(map[string]func() ([]upstream.Upstream, error))
	for _, rule := range q.conf.Rules {
		for _, addr := range rule.Resolvers {
			if _, ok := q.upstreams[addr]; ok {
				continue
			}
			var f func() ([]upstream.Upstream, error)
			if strings.HasPrefix(addr, "resolvconf://") {
				location := strings.TrimPrefix(addr, "resolvconf://")
				f = (&resolvconf{location: location}).GetUpstreams
			} else {
				u, err := upstream.AddressToUpstream(addr, upstream.Options{Timeout: 15 * time.Second})
				if err != nil {
					return fmt.Errorf("failed to create upstream %s: %s", addr, err)
				}
				f = func(u upstream.Upstream) func() ([]upstream.Upstream, error) {
					return func() ([]upstream.Upstream, error) {
						return []upstream.Upstream{u}, nil
					}
				}(u)
			}
			q.upstreams[addr] = f
		}
	}

	errs := make(chan error, len(q.conf.Server.Listeners))
	servers := make([]*dns.Server, 0, len(q.conf.Server.Listeners))
	for _, addr := range q.conf.Server.Listeners {
		u, err := url.Parse(addr)
		if err != nil {
			return err
		}
		s := &dns.Server{Net: u.Scheme, Addr: u.Host, Handler: q}
		go func(s *dns.Server) {
			log.Println("I listen on", fmt.Sprintf("%s://%s", s.Net, s.Addr))
			err := s.ListenAndServe()
			errs <- err
		}(s)
		go func(s *dns.Server) {
			s.Shutdown()
		}(s)
		servers = append(servers, s)
	}
	stop := make(chan os.Signal, 1)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)
	defer signal.Reset(os.Interrupt, syscall.SIGTERM)
	defer close(stop)
	go func() {
		sig := <-stop
		log.Println("I shutdown by", sig)
		for _, s := range servers {
			s.Shutdown()
		}
	}()

	var err error
	for _ = range q.conf.Server.Listeners {
		err = <-errs
	}
	return err
}

type Rule struct {
	DomainSuffix []string `yaml:"domain-suffix"`
	Resolvers    []string `yaml:"resolvers"`
	IPSet        string   `yaml:"ipset"`
}

type Config struct {
	Server struct {
		Listeners []string `yaml:"listeners"`
		CacheSize int      `yaml:"cache-size"`
	} `yaml:"server"`
	Rules []Rule `yaml:"rules"`
}

func loadConfig(path string) (conf Config, err error) {
	content, err := ioutil.ReadFile(path)
	if err != nil {
		err = fmt.Errorf("failed to load config: %s: %s", path, err)
		return
	}
	err = yaml.Unmarshal(content, &conf)
	if err != nil {
		err = fmt.Errorf("failed to parse config: %s", err)
		return
	}

	if len(conf.Server.Listeners) == 0 {
		err = fmt.Errorf("config error: at least one listener are required")
		return
	}
	if conf.Server.CacheSize <= 0 {
		conf.Server.CacheSize = 1000
	}

	for _, rule := range conf.Rules {
		if len(rule.Resolvers) == 0 {
			err = fmt.Errorf("config err: every rule must has resolvers")
			return
		}
		for i := range rule.DomainSuffix {
			rule.DomainSuffix[i] = strings.TrimRight(rule.DomainSuffix[i], ".") + "."
		}
	}
	return
}

var (
	isIPSetCmd = 2
)

func hasIPSetCmd() bool {
	if isIPSetCmd == 2 {
		_, err := exec.Command("ipset", "version").CombinedOutput()
		if err != nil {
			log.Println("W ipset command not found")
			isIPSetCmd = 0
		} else {
			isIPSetCmd = 1
		}
	}
	return isIPSetCmd == 1
}

func ipsetAdd(setName, ip string) error {

	cmd := exec.Command("ipset", "add", setName, ip)
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

type Cache struct {
	mu        sync.Mutex
	cacheSize int
	items     map[string]*cacheItem
	lru       *list.List
}

func NewCache(cacheSize int) *Cache {
	return &Cache{cacheSize: cacheSize, items: make(map[string]*cacheItem), lru: list.New()}
}

func (c *Cache) GetOrCreate(req *dns.Msg, f func() (*dns.Msg, upstream.Upstream, error)) (*dns.Msg, upstream.Upstream, bool, error) {
	msg, u, err := f()
	return msg, u, false, err
}

func (c *Cache) expireLocked() {
	now := time.Now()
	for {
		back := c.lru.Back()
		if back == nil {
			break
		}
		key := back.Value.(string)
		item, ok := c.items[key]
		if ok && item.expiredAt.Before(now) {
			c.lru.Remove(back)
			delete(c.items, key)
		} else {
			break
		}
	}
}

type cacheItem struct {
	lruRef    *list.Element
	done      chan error
	msg       *dns.Msg
	u         upstream.Upstream
	err       error
	expiredAt time.Time
}

func (ci *cacheItem) Get() (*dns.Msg, upstream.Upstream, error) {
	err := <-ci.done
	return ci.msg, ci.u, err
}

type resolvconf struct {
	location   string
	upstreams  []upstream.Upstream
	lastModify time.Time
}

var nsRegex = regexp.MustCompile(`nameserver\s+([\w.:]+)`)

func (r *resolvconf) GetUpstreams() ([]upstream.Upstream, error) {
	stat, err := os.Stat(r.location)
	if err != nil {
		return nil, err
	}
	if r.lastModify.Before(stat.ModTime()) {
		content, err := ioutil.ReadFile(r.location)
		if err != nil {
			return nil, err
		}
		text := removeComments(string(content))

		var upstreams []upstream.Upstream
		for _, match := range nsRegex.FindAllStringSubmatch(text, -1) {
			addr := match[1]
			u, err := upstream.AddressToUpstream(addr, upstream.Options{Timeout: 15 * time.Second})
			if err != nil {
				return nil, err
			}
			upstreams = append(upstreams, u)
		}
		r.upstreams = upstreams
	}

	if len(r.upstreams) == 0 {
		return nil, errors.New("no upstream found in file://" + r.location)
	}

	return r.upstreams, nil
}

func removeComments(content string) string {
	lines := strings.Split(content, "\n")
	for i := 0; i < len(lines); i++ {
		line := lines[i]
		commentIdx := strings.Index(line, "#")
		if commentIdx > -1 {
			lines[0] = line[:commentIdx]
		}
	}
	return strings.Join(lines, "\n")
}
