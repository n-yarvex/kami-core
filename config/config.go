package config

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"reflect"
	"strings"
	"time"

	"github.com/n-yarvex/kami-core/klog"
)

type Config struct {
	Log       klog.Options      `json:"log"`
	DNS       DNS               `json:"dns"`
	Inbounds  []json.RawMessage `json:"inbounds"`
	Outbounds []json.RawMessage `json:"outbounds"`
	Route     Route             `json:"route"`
	API       *API              `json:"api,omitempty"`
}

type DNS struct {
	Servers   []DNSServer         `json:"servers"`
	Rules     []DNSRule           `json:"rules"`
	Final     string              `json:"final"`
	Strategy  string              `json:"strategy"`
	CacheSize int                 `json:"cache_size"`
	Hosts     map[string][]string `json:"hosts"`
}

type DNSServer struct {
	Tag     string `json:"tag"`
	Address string `json:"address"`
	Detour  string `json:"detour"`
}

type DNSRule struct {
	Domain        []string `json:"domain"`
	DomainSuffix  []string `json:"domain_suffix"`
	DomainKeyword []string `json:"domain_keyword"`
	DomainRegex   []string `json:"domain_regex"`
	RuleSet       []string `json:"rule_set"`
	Server        string   `json:"server"`
}

type Route struct {
	Rules    []Rule    `json:"rules"`
	Final    string    `json:"final"`
	RuleSets []RuleSet `json:"rule_sets"`
}

type Rule struct {
	Inbound       []string `json:"inbound"`
	Network       string   `json:"network"`
	Protocol      []string `json:"protocol"`
	Domain        []string `json:"domain"`
	DomainSuffix  []string `json:"domain_suffix"`
	DomainKeyword []string `json:"domain_keyword"`
	DomainRegex   []string `json:"domain_regex"`
	IPCIDR        []string `json:"ip_cidr"`
	SourceIPCIDR  []string `json:"source_ip_cidr"`
	Port          []string `json:"port"`
	SourcePort    []string `json:"source_port"`
	User          []string `json:"user"`
	RuleSet       []string `json:"rule_set"`
	Invert        bool     `json:"invert"`
	Outbound      string   `json:"outbound"`
}

type RuleSet struct {
	Tag   string   `json:"tag"`
	File  string   `json:"file"`
	Items []string `json:"items"`
}

type API struct {
	Listen string `json:"listen"`
	Secret string `json:"secret"`
}

type InboundCommon struct {
	Type         string `json:"type"`
	Tag          string `json:"tag"`
	Listen       string `json:"listen"`
	Sniff        bool   `json:"sniff"`
	AllowPrivate *bool  `json:"allow_private"`
}

type OutboundCommon struct {
	Type           string   `json:"type"`
	Tag            string   `json:"tag"`
	Detour         string   `json:"detour"`
	BindInterface  string   `json:"bind_interface"`
	RoutingMark    uint32   `json:"routing_mark"`
	ConnectTimeout Duration `json:"connect_timeout"`
	DomainStrategy string   `json:"domain_strategy"`
}

type Duration time.Duration

func (d *Duration) UnmarshalJSON(b []byte) error {
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		return err
	}
	switch x := v.(type) {
	case float64:
		*d = Duration(time.Duration(x * float64(time.Second)))
	case string:
		p, err := time.ParseDuration(x)
		if err != nil {
			return fmt.Errorf("bad duration %q", x)
		}
		*d = Duration(p)
	default:
		return errors.New("duration must be a string like \"30s\" or a number of seconds")
	}
	return nil
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return json.Marshal(time.Duration(d).String())
}

func (d Duration) Std() time.Duration { return time.Duration(d) }

func StripComments(src []byte) []byte {
	out := make([]byte, 0, len(src))
	for i := 0; i < len(src); i++ {
		c := src[i]
		switch {
		case c == '"':
			out = append(out, c)
			for i++; i < len(src); i++ {
				out = append(out, src[i])
				if src[i] == '\\' && i+1 < len(src) {
					i++
					out = append(out, src[i])
				} else if src[i] == '"' {
					break
				}
			}
		case c == '/' && i+1 < len(src) && src[i+1] == '/':
			for i < len(src) && src[i] != '\n' {
				i++
			}
			out = append(out, '\n')
		case c == '/' && i+1 < len(src) && src[i+1] == '*':
			i += 2
			for i+1 < len(src) && !(src[i] == '*' && src[i+1] == '/') {
				if src[i] == '\n' {
					out = append(out, '\n')
				}
				i++
			}
			i++
		default:
			out = append(out, c)
		}
	}
	return out
}

func Parse(data []byte) (*Config, error) {
	dec := json.NewDecoder(bytes.NewReader(StripComments(data)))
	dec.DisallowUnknownFields()
	var c Config
	if err := dec.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	if dec.More() {
		return nil, errors.New("config: trailing data after the top-level object")
	}
	return &c, c.Validate()
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data)
}

func Split(raw json.RawMessage, common any) (json.RawMessage, error) {
	var all map[string]json.RawMessage
	if err := json.Unmarshal(raw, &all); err != nil {
		return nil, fmt.Errorf("not a JSON object: %w", err)
	}
	t := reflect.TypeOf(common).Elem()
	mine := make(map[string]json.RawMessage)
	for i := 0; i < t.NumField(); i++ {
		name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ",")
		if v, ok := all[name]; ok {
			mine[name] = v
			delete(all, name)
		}
	}
	head, _ := json.Marshal(mine)
	if err := json.Unmarshal(head, common); err != nil {
		return nil, err
	}
	rest, err := json.Marshal(all)
	return rest, err
}

func (c *Config) Validate() error {
	tags := map[string]string{}
	for i, raw := range c.Inbounds {
		var ic InboundCommon
		if _, err := Split(raw, &ic); err != nil {
			return fmt.Errorf("inbounds[%d]: %w", i, err)
		}
		if ic.Type == "" || ic.Tag == "" {
			return fmt.Errorf("inbounds[%d]: type and tag are required", i)
		}
		if prev, dup := tags["in:"+ic.Tag]; dup {
			return fmt.Errorf("inbounds[%d]: tag %q already used by %s", i, ic.Tag, prev)
		}
		tags["in:"+ic.Tag] = ic.Type
	}
	outs := map[string]OutboundCommon{}
	for i, raw := range c.Outbounds {
		var oc OutboundCommon
		if _, err := Split(raw, &oc); err != nil {
			return fmt.Errorf("outbounds[%d]: %w", i, err)
		}
		if oc.Type == "" || oc.Tag == "" {
			return fmt.Errorf("outbounds[%d]: type and tag are required", i)
		}
		if _, dup := outs[oc.Tag]; dup {
			return fmt.Errorf("outbounds[%d]: tag %q is used twice", i, oc.Tag)
		}
		outs[oc.Tag] = oc
	}
	for tag, oc := range outs {
		if oc.Detour != "" {
			if _, ok := outs[oc.Detour]; !ok {
				return fmt.Errorf("outbound %q: detour %q does not exist", tag, oc.Detour)
			}
			if oc.Detour == tag {
				return fmt.Errorf("outbound %q: detour points at itself", tag)
			}
		}
	}
	sets := map[string]bool{}
	for _, s := range c.Route.RuleSets {
		if s.Tag == "" || sets[s.Tag] {
			return fmt.Errorf("route.rule_sets: empty or duplicate tag %q", s.Tag)
		}
		if s.File == "" && len(s.Items) == 0 {
			return fmt.Errorf("route.rule_sets %q: needs file or items", s.Tag)
		}
		sets[s.Tag] = true
	}
	for i, r := range c.Route.Rules {
		if _, ok := outs[r.Outbound]; !ok {
			return fmt.Errorf("route.rules[%d]: outbound %q does not exist", i, r.Outbound)
		}
		for _, s := range r.RuleSet {
			if !sets[s] {
				return fmt.Errorf("route.rules[%d]: unknown rule_set %q", i, s)
			}
		}
		for _, in := range r.Inbound {
			if _, ok := tags["in:"+in]; !ok {
				return fmt.Errorf("route.rules[%d]: unknown inbound %q", i, in)
			}
		}
		if r.Network != "" && r.Network != "tcp" && r.Network != "udp" {
			return fmt.Errorf("route.rules[%d]: network must be tcp or udp", i)
		}
	}
	if c.Route.Final != "" {
		if _, ok := outs[c.Route.Final]; !ok {
			return fmt.Errorf("route.final: outbound %q does not exist", c.Route.Final)
		}
	}
	servers := map[string]bool{}
	for _, s := range c.DNS.Servers {
		if s.Tag == "" || s.Address == "" || servers[s.Tag] {
			return fmt.Errorf("dns.servers: bad or duplicate entry %q", s.Tag)
		}
		if s.Detour != "" {
			if _, ok := outs[s.Detour]; !ok {
				return fmt.Errorf("dns.servers %q: detour %q does not exist", s.Tag, s.Detour)
			}
		}
		servers[s.Tag] = true
	}
	for i, r := range c.DNS.Rules {
		if !servers[r.Server] {
			return fmt.Errorf("dns.rules[%d]: unknown server %q", i, r.Server)
		}
		for _, s := range r.RuleSet {
			if !sets[s] {
				return fmt.Errorf("dns.rules[%d]: unknown rule_set %q", i, s)
			}
		}
	}
	if c.DNS.Final != "" && !servers[c.DNS.Final] {
		return fmt.Errorf("dns.final: unknown server %q", c.DNS.Final)
	}
	switch c.DNS.Strategy {
	case "", "prefer_ipv4", "prefer_ipv6", "ipv4_only", "ipv6_only":
	default:
		return fmt.Errorf("dns.strategy: unknown value %q", c.DNS.Strategy)
	}
	return nil
}
