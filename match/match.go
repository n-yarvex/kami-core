package match

import (
	"bufio"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

type Domains struct {
	full    map[string]struct{}
	suffix  map[string]struct{}
	keyword []string
	regex   []*regexp.Regexp
}

func clean(s string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
}

func (d *Domains) AddFull(s string) {
	if d.full == nil {
		d.full = map[string]struct{}{}
	}
	d.full[clean(s)] = struct{}{}
}

func (d *Domains) AddSuffix(s string) {
	if d.suffix == nil {
		d.suffix = map[string]struct{}{}
	}
	d.suffix[strings.TrimPrefix(clean(s), ".")] = struct{}{}
}

func (d *Domains) AddKeyword(s string) { d.keyword = append(d.keyword, strings.ToLower(s)) }

func (d *Domains) AddRegex(s string) error {
	re, err := regexp.Compile(s)
	if err != nil {
		return fmt.Errorf("bad regexp %q: %w", s, err)
	}
	d.regex = append(d.regex, re)
	return nil
}

func (d *Domains) Empty() bool {
	return len(d.full) == 0 && len(d.suffix) == 0 && len(d.keyword) == 0 && len(d.regex) == 0
}

func (d *Domains) Match(host string) bool {
	host = clean(host)
	if host == "" {
		return false
	}
	if _, ok := d.full[host]; ok {
		return true
	}
	for rest := host; ; {
		if _, ok := d.suffix[rest]; ok {
			return true
		}
		i := strings.IndexByte(rest, '.')
		if i < 0 {
			break
		}
		rest = rest[i+1:]
	}
	for _, k := range d.keyword {
		if strings.Contains(host, k) {
			return true
		}
	}
	for _, re := range d.regex {
		if re.MatchString(host) {
			return true
		}
	}
	return false
}

type Prefixes struct {
	bits []int
	sets map[int]map[netip.Prefix]struct{}
}

func (p *Prefixes) Add(pf netip.Prefix) {
	pf = netip.PrefixFrom(pf.Addr().Unmap(), pf.Bits()).Masked()
	if p.sets == nil {
		p.sets = map[int]map[netip.Prefix]struct{}{}
	}
	key := pf.Bits()
	if pf.Addr().Is6() {
		key += 1000
	}
	m := p.sets[key]
	if m == nil {
		m = map[netip.Prefix]struct{}{}
		p.sets[key] = m
		p.bits = append(p.bits, key)
		sort.Sort(sort.Reverse(sort.IntSlice(p.bits)))
	}
	m[pf] = struct{}{}
}

func (p *Prefixes) AddText(s string) error {
	s = strings.TrimSpace(s)
	if strings.Contains(s, "/") {
		pf, err := netip.ParsePrefix(s)
		if err != nil {
			return fmt.Errorf("bad cidr %q", s)
		}
		p.Add(pf)
		return nil
	}
	ip, err := netip.ParseAddr(s)
	if err != nil {
		return fmt.Errorf("bad ip %q", s)
	}
	ip = ip.Unmap()
	p.Add(netip.PrefixFrom(ip, ip.BitLen()))
	return nil
}

func (p *Prefixes) Empty() bool { return len(p.bits) == 0 }

func (p *Prefixes) Contains(ip netip.Addr) bool {
	ip = ip.Unmap()
	for _, key := range p.bits {
		bits, v6 := key, false
		if key >= 1000 {
			bits, v6 = key-1000, true
		}
		if v6 != ip.Is6() {
			continue
		}
		pf, err := ip.Prefix(bits)
		if err != nil {
			continue
		}
		if _, ok := p.sets[key][pf]; ok {
			return true
		}
	}
	return false
}

type Ports struct {
	ranges [][2]uint16
}

func ParsePorts(items []string) (*Ports, error) {
	p := &Ports{}
	for _, it := range items {
		lo, hi, isRange := strings.Cut(strings.TrimSpace(it), ":")
		a, b := uint64(0), uint64(65535)
		var err error
		if lo != "" {
			if a, err = strconv.ParseUint(lo, 10, 16); err != nil {
				return nil, fmt.Errorf("bad port %q", it)
			}
		}
		if !isRange {
			b = a
		} else if hi != "" {
			if b, err = strconv.ParseUint(hi, 10, 16); err != nil {
				return nil, fmt.Errorf("bad port %q", it)
			}
		}
		if lo == "" && hi == "" || a > b {
			return nil, fmt.Errorf("bad port range %q", it)
		}
		p.ranges = append(p.ranges, [2]uint16{uint16(a), uint16(b)})
	}
	return p, nil
}

func (p *Ports) Empty() bool { return p == nil || len(p.ranges) == 0 }

func (p *Ports) Has(port uint16) bool {
	for _, r := range p.ranges {
		if port >= r[0] && port <= r[1] {
			return true
		}
	}
	return false
}

type Set struct {
	Domains  Domains
	Prefixes Prefixes
}

func (s *Set) AddLine(line string) error {
	line = strings.TrimSpace(line)
	if i := strings.Index(line, "#"); i >= 0 {
		line = strings.TrimSpace(line[:i])
	}
	if line == "" {
		return nil
	}
	kind, val, found := strings.Cut(line, ":")
	if found && !strings.Contains(kind, ".") && !strings.Contains(kind, "]") && len(kind) < 10 {
		switch kind {
		case "full":
			s.Domains.AddFull(val)
		case "domain", "suffix":
			s.Domains.AddSuffix(val)
		case "keyword":
			s.Domains.AddKeyword(val)
		case "regexp", "regex":
			return s.Domains.AddRegex(val)
		case "ip", "cidr":
			return s.Prefixes.AddText(val)
		default:
			return fmt.Errorf("unknown rule type %q", kind)
		}
		return nil
	}
	if err := s.Prefixes.AddText(line); err == nil {
		return nil
	}
	if strings.ContainsAny(line, " /") {
		return fmt.Errorf("cannot read rule %q", line)
	}
	s.Domains.AddSuffix(line)
	return nil
}

func LoadSet(file string, items []string) (*Set, error) {
	s := &Set{}
	if file != "" {
		f, err := os.Open(file)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 64<<10), 1<<20)
		for n := 1; sc.Scan(); n++ {
			if err := s.AddLine(sc.Text()); err != nil {
				return nil, fmt.Errorf("%s:%d: %w", file, n, err)
			}
		}
		if err := sc.Err(); err != nil {
			return nil, err
		}
	}
	for _, it := range items {
		if err := s.AddLine(it); err != nil {
			return nil, err
		}
	}
	if s.Domains.Empty() && s.Prefixes.Empty() {
		return nil, errors.New("rule set is empty")
	}
	return s, nil
}
