package dns

import (
	"container/list"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/match"
)

const (
	minTTL      = 10 * time.Second
	maxTTL      = time.Hour
	negativeTTL = 30 * time.Second
)

type rule struct {
	domains match.Domains
	sets    []*match.Set
	server  string
}

type cacheKey struct {
	name  string
	qtype dnsmessage.Type
}

type cached struct {
	key     cacheKey
	ans     answer
	expires time.Time
}

type call struct {
	done chan struct{}
	ans  answer
	err  error
}

type Resolver struct {
	log      *slog.Logger
	servers  map[string]upstream
	fallback string
	rules    []rule
	strategy string
	hosts    map[string][]netip.Addr

	mu       sync.Mutex
	lru      *list.List
	index    map[cacheKey]*list.Element
	capacity int
	flight   map[string]*call
}

type Deps struct {
	Log      *slog.Logger
	RuleSets map[string]*match.Set
	DialFor  func(detour string) (DialFunc, error)
}

func New(cfg config.DNS, deps Deps) (*Resolver, error) {
	r := &Resolver{
		log:      deps.Log,
		servers:  map[string]upstream{},
		strategy: cfg.Strategy,
		hosts:    map[string][]netip.Addr{},
		lru:      list.New(),
		index:    map[cacheKey]*list.Element{},
		capacity: cfg.CacheSize,
		flight:   map[string]*call{},
	}
	if r.capacity == 0 {
		r.capacity = 2048
	}
	for _, s := range cfg.Servers {
		dial, err := deps.DialFor(s.Detour)
		if err != nil {
			return nil, fmt.Errorf("dns server %q: %w", s.Tag, err)
		}
		up, err := parseServer(s.Address, dial)
		if err != nil {
			return nil, fmt.Errorf("dns server %q: %w", s.Tag, err)
		}
		r.servers[s.Tag] = up
		if r.fallback == "" {
			r.fallback = s.Tag
		}
	}
	if cfg.Final != "" {
		r.fallback = cfg.Final
	}
	if r.fallback == "" {
		r.servers["local"] = systemUpstream{}
		r.fallback = "local"
	}
	for i, dr := range cfg.Rules {
		ru := rule{server: dr.Server}
		for _, d := range dr.Domain {
			ru.domains.AddFull(d)
		}
		for _, d := range dr.DomainSuffix {
			ru.domains.AddSuffix(d)
		}
		for _, d := range dr.DomainKeyword {
			ru.domains.AddKeyword(d)
		}
		for _, d := range dr.DomainRegex {
			if err := ru.domains.AddRegex(d); err != nil {
				return nil, fmt.Errorf("dns.rules[%d]: %w", i, err)
			}
		}
		for _, tag := range dr.RuleSet {
			ru.sets = append(ru.sets, deps.RuleSets[tag])
		}
		r.rules = append(r.rules, ru)
	}
	for host, list := range cfg.Hosts {
		for _, s := range list {
			ip, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("dns.hosts[%q]: %q is not an address", host, s)
			}
			key := strings.ToLower(strings.TrimSuffix(host, "."))
			r.hosts[key] = append(r.hosts[key], ip.Unmap())
		}
	}
	return r, nil
}

func (r *Resolver) pick(host string) string {
	for _, ru := range r.rules {
		hit := !ru.domains.Empty() && ru.domains.Match(host)
		for _, s := range ru.sets {
			if !hit && s != nil && s.Domains.Match(host) {
				hit = true
			}
		}
		if hit {
			return ru.server
		}
	}
	return r.fallback
}

func (r *Resolver) Lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	return r.LookupStrategy(ctx, host, r.strategy)
}

func (r *Resolver) LookupStrategy(ctx context.Context, host, strategy string) ([]netip.Addr, error) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if host == "" {
		return nil, errors.New("dns: empty host name")
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	if ips, ok := r.hosts[host]; ok {
		return filterFamily(ips, strategy), nil
	}
	want4, want6 := strategy != "ipv6_only", strategy != "ipv4_only"
	type result struct {
		ips []netip.Addr
		err error
	}
	var v4, v6 result
	var wg sync.WaitGroup
	run := func(on bool, qtype dnsmessage.Type, out *result) {
		if !on {
			return
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ips, err := r.ask(ctx, host, qtype)
			*out = result{ips, err}
		}()
	}
	run(want4, dnsmessage.TypeA, &v4)
	run(want6, dnsmessage.TypeAAAA, &v6)
	wg.Wait()
	first, second := v4.ips, v6.ips
	if strategy == "prefer_ipv6" {
		first, second = v6.ips, v4.ips
	}
	out := append(append([]netip.Addr(nil), first...), second...)
	if len(out) > 0 {
		return out, nil
	}
	if err := errors.Join(v4.err, v6.err); err != nil {
		return nil, err
	}
	return nil, fmt.Errorf("dns: no address for %s", host)
}

func filterFamily(ips []netip.Addr, strategy string) []netip.Addr {
	switch strategy {
	case "ipv4_only":
		var out []netip.Addr
		for _, ip := range ips {
			if ip.Is4() {
				out = append(out, ip)
			}
		}
		return out
	case "ipv6_only":
		var out []netip.Addr
		for _, ip := range ips {
			if ip.Is6() {
				out = append(out, ip)
			}
		}
		return out
	}
	return append([]netip.Addr(nil), ips...)
}

func (r *Resolver) ask(ctx context.Context, host string, qtype dnsmessage.Type) ([]netip.Addr, error) {
	key := cacheKey{host, qtype}
	if ans, ok := r.cacheGet(key); ok {
		return addrs(ans), nil
	}
	flightKey := fmt.Sprintf("%s|%d", host, qtype)
	r.mu.Lock()
	if c, ok := r.flight[flightKey]; ok {
		r.mu.Unlock()
		select {
		case <-c.done:
			return addrs(c.ans), c.err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	c := &call{done: make(chan struct{})}
	r.flight[flightKey] = c
	r.mu.Unlock()

	tag := r.pick(host)
	qctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 10*time.Second)
	c.ans, c.err = r.servers[tag].query(qctx, host, qtype)
	cancel()
	if c.err == nil {
		r.cachePut(key, c.ans)
		r.log.Debug("dns", "name", host, "type", qtype.String(), "server", tag, "answers", len(c.ans.records))
	}
	r.mu.Lock()
	delete(r.flight, flightKey)
	r.mu.Unlock()
	close(c.done)
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	default:
	}
	return addrs(c.ans), c.err
}

func addrs(a answer) []netip.Addr {
	out := make([]netip.Addr, len(a.records))
	for i, rec := range a.records {
		out[i] = rec.ip
	}
	return out
}

func ttlOf(a answer) time.Duration {
	if len(a.records) == 0 {
		return negativeTTL
	}
	ttl := maxTTL
	for _, rec := range a.records {
		ttl = min(ttl, time.Duration(rec.ttl)*time.Second)
	}
	return max(ttl, minTTL)
}

func (r *Resolver) cacheGet(key cacheKey) (answer, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	el, ok := r.index[key]
	if !ok {
		return answer{}, false
	}
	e := el.Value.(*cached)
	if time.Now().After(e.expires) {
		r.lru.Remove(el)
		delete(r.index, key)
		return answer{}, false
	}
	r.lru.MoveToFront(el)
	return e.ans, true
}

func (r *Resolver) cachePut(key cacheKey, a answer) {
	r.mu.Lock()
	defer r.mu.Unlock()
	e := &cached{key: key, ans: a, expires: time.Now().Add(ttlOf(a))}
	if el, ok := r.index[key]; ok {
		el.Value = e
		r.lru.MoveToFront(el)
		return
	}
	r.index[key] = r.lru.PushFront(e)
	for r.lru.Len() > r.capacity {
		last := r.lru.Back()
		delete(r.index, last.Value.(*cached).key)
		r.lru.Remove(last)
	}
}

func (r *Resolver) Flush() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lru.Init()
	r.index = map[cacheKey]*list.Element{}
}
