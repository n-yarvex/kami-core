package route

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"strings"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/match"
)

type rule struct {
	inbound   []string
	network   string
	protocol  []string
	domains   match.Domains
	hasDomain bool
	ips       match.Prefixes
	sources   match.Prefixes
	ports     *match.Ports
	srcPorts  *match.Ports
	users     []string
	sets      []*match.Set
	invert    bool
	outbound  string
}

type Engine struct {
	rules []*rule
	final string
}

func LoadSets(items []config.RuleSet) (map[string]*match.Set, error) {
	out := make(map[string]*match.Set, len(items))
	for _, it := range items {
		s, err := match.LoadSet(it.File, it.Items)
		if err != nil {
			return nil, fmt.Errorf("rule_set %q: %w", it.Tag, err)
		}
		out[it.Tag] = s
	}
	return out, nil
}

func Compile(cfg config.Route, sets map[string]*match.Set, fallback string) (*Engine, error) {
	e := &Engine{final: cfg.Final}
	if e.final == "" {
		e.final = fallback
	}
	for i, r := range cfg.Rules {
		c := &rule{
			inbound:  r.Inbound,
			network:  r.Network,
			protocol: r.Protocol,
			users:    r.User,
			invert:   r.Invert,
			outbound: r.Outbound,
		}
		for _, d := range r.Domain {
			c.domains.AddFull(d)
		}
		for _, d := range r.DomainSuffix {
			c.domains.AddSuffix(d)
		}
		for _, d := range r.DomainKeyword {
			c.domains.AddKeyword(d)
		}
		for _, d := range r.DomainRegex {
			if err := c.domains.AddRegex(d); err != nil {
				return nil, fmt.Errorf("route.rules[%d]: %w", i, err)
			}
		}
		c.hasDomain = !c.domains.Empty()
		for _, s := range r.IPCIDR {
			if err := c.ips.AddText(s); err != nil {
				return nil, fmt.Errorf("route.rules[%d].ip_cidr: %w", i, err)
			}
		}
		for _, s := range r.SourceIPCIDR {
			if err := c.sources.AddText(s); err != nil {
				return nil, fmt.Errorf("route.rules[%d].source_ip_cidr: %w", i, err)
			}
		}
		var err error
		if len(r.Port) > 0 {
			if c.ports, err = match.ParsePorts(r.Port); err != nil {
				return nil, fmt.Errorf("route.rules[%d].port: %w", i, err)
			}
		}
		if len(r.SourcePort) > 0 {
			if c.srcPorts, err = match.ParsePorts(r.SourcePort); err != nil {
				return nil, fmt.Errorf("route.rules[%d].source_port: %w", i, err)
			}
		}
		for _, tag := range r.RuleSet {
			s, ok := sets[tag]
			if !ok {
				return nil, fmt.Errorf("route.rules[%d]: rule_set %q is not loaded", i, tag)
			}
			c.sets = append(c.sets, s)
		}
		e.rules = append(e.rules, c)
	}
	return e, nil
}

func (r *rule) needsIP() bool {
	if !r.ips.Empty() {
		return true
	}
	for _, s := range r.sets {
		if !s.Prefixes.Empty() {
			return true
		}
	}
	return false
}

type Lookup func(ctx context.Context, host string) ([]netip.Addr, error)

func (e *Engine) Final() string { return e.final }

func (e *Engine) Match(ctx context.Context, md adapter.Metadata, lookup Lookup) string {
	var resolved []netip.Addr
	var resolvedOnce bool
	destIPs := func() []netip.Addr {
		if md.Dest.IsIP() {
			return []netip.Addr{md.Dest.IP()}
		}
		if !resolvedOnce {
			resolvedOnce = true
			if lookup != nil {
				if host := md.Target().Host(); host != "" {
					resolved, _ = lookup(ctx, host)
				}
			}
		}
		return resolved
	}
	host := ""
	if md.Domain != "" {
		host = md.Domain
	} else if md.Dest.IsDomain() {
		host = md.Dest.Host()
	}
	for _, r := range e.rules {
		if r.matches(md, host, destIPs) != r.invert {
			return r.outbound
		}
	}
	return e.final
}

func (r *rule) matches(md adapter.Metadata, host string, destIPs func() []netip.Addr) bool {
	if len(r.inbound) > 0 && !slices.Contains(r.inbound, md.Inbound) {
		return false
	}
	if r.network != "" && r.network != md.Network {
		return false
	}
	if len(r.protocol) > 0 && !slices.Contains(r.protocol, md.Protocol) {
		return false
	}
	if len(r.users) > 0 && !slices.Contains(r.users, md.User) {
		return false
	}
	if !r.ports.Empty() && !r.ports.Has(md.Dest.Port()) {
		return false
	}
	if !r.srcPorts.Empty() && !r.srcPorts.Has(md.Source.Port()) {
		return false
	}
	if !r.sources.Empty() && !(md.Source.IsIP() && r.sources.Contains(md.Source.IP())) {
		return false
	}
	if r.hasDomain && !r.domains.Match(host) {
		return false
	}
	if !r.ips.Empty() && !anyIn(&r.ips, destIPs()) {
		return false
	}
	if len(r.sets) > 0 {
		hit := false
		for _, s := range r.sets {
			if (host != "" && s.Domains.Match(host)) || (!s.Prefixes.Empty() && anyIn(&s.Prefixes, destIPs())) {
				hit = true
				break
			}
		}
		if !hit {
			return false
		}
	}
	return true
}

func anyIn(p *match.Prefixes, ips []netip.Addr) bool {
	for _, ip := range ips {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

func (e *Engine) NeedsIP() bool {
	for _, r := range e.rules {
		if r.needsIP() {
			return true
		}
	}
	return false
}

func IsInternal(ip netip.Addr) bool {
	ip = ip.Unmap()
	return ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() ||
		ip.IsUnspecified() || ip.IsMulticast() || cgnat.Contains(ip) || strings.HasPrefix(ip.String(), "0.")
}

var cgnat = netip.MustParsePrefix("100.64.0.0/10")
