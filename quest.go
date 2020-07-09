package main

import (
	"bytes"
	"container/list"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"math"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
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
	upstreams map[string]upstream.Upstream
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
		upstreams := []upstream.Upstream{}
		for _, addr := range rule.Resolvers {
			u := q.upstreams[addr]
			log.Printf("D %s %s -> %s\n", w.RemoteAddr(), domain, u.Address())
			upstreams = append(upstreams, u)
		}
		resp, u, err := upstream.ExchangeParallel(upstreams, req)
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
	q.upstreams = make(map[string]upstream.Upstream)
	for _, rule := range q.conf.Rules {
		for _, addr := range rule.Resolvers {
			if _, ok := q.upstreams[addr]; ok {
				continue
			}
			u, err := upstream.AddressToUpstream(addr, upstream.Options{Timeout: 15 * time.Second})
			if err != nil {
				return fmt.Errorf("failed to create upstream %s: %s", addr, err)
			}
			q.upstreams[addr] = u
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
	key := msgKey(req)
	c.mu.Lock()

	c.expireLocked()

	item, ok := c.items[key]

	// cache hit, but should expire, we remove it and resolve it again
	if ok {
		select {
		case <-item.done:
			if item.expiredAt.Before(time.Now()) {
				remove := c.lru.Remove(item.lruRef).(string)
				delete(c.items, remove)
				ok = false
			}
		default:
		}
	}

	if !ok {
		if len(c.items) >= c.cacheSize {
			evicted := c.lru.Remove(c.lru.Back()).(string)
			delete(c.items, evicted)
		}
		item = &cacheItem{
			lruRef: c.lru.PushFront(key),
			done:   make(chan error, 0),
		}
		c.items[key] = item
		c.mu.Unlock()

		item.msg, item.u, item.err = f()
		if item.err != nil {
			c.mu.Lock()
			c.lru.Remove(item.lruRef)
			delete(c.items, key)
			c.mu.Unlock()
		} else {
			var minTtl uint32 = math.MaxUint32
			for _, rr := range item.msg.Answer {
				if rr.Header().Ttl < minTtl {
					minTtl = rr.Header().Ttl
				}
			}
			item.expiredAt = time.Now().Add(time.Duration(minTtl) * time.Second)
		}

		close(item.done)
		return item.msg, item.u, false, item.err
	} else {
		c.lru.MoveToFront(item.lruRef)
		c.mu.Unlock()
		msg, u, err := item.Get()
		resp := msg.Copy()
		for _, rr := range resp.Answer {
			rr.Header().Ttl = uint32(time.Until(item.expiredAt).Seconds())
		}
		resp.Id = req.Id
		return resp, u, true, err
	}
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
