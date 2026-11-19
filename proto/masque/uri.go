package masque

import (
	"errors"
	"fmt"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/n-yarvex/kami-core/addr"
)

type template struct {
	pattern *regexp.Regexp
	pieces  []piece
}

type piece struct {
	literal  string
	variable string
}

var varRe = regexp.MustCompile(`\{([a-z_]+)\}`)

func compileTemplate(s string) (*template, error) {
	if s == "" {
		s = DefaultTemplate
	}
	if !strings.HasPrefix(s, "/") {
		return nil, errors.New("masque: path template must start with '/'")
	}
	t := &template{}
	var re strings.Builder
	re.WriteString("^")
	seen := map[string]bool{}
	last := 0
	for _, m := range varRe.FindAllStringSubmatchIndex(s, -1) {
		lit := s[last:m[0]]
		name := s[m[2]:m[3]]
		if name != "target_host" && name != "target_port" {
			return nil, fmt.Errorf("masque: unknown template variable {%s}", name)
		}
		if seen[name] {
			return nil, fmt.Errorf("masque: template variable {%s} used twice", name)
		}
		seen[name] = true
		t.pieces = append(t.pieces, piece{literal: lit}, piece{variable: name})
		re.WriteString(regexp.QuoteMeta(lit))
		re.WriteString("(?P<" + name + ">[^/?&#=]+)")
		last = m[1]
	}
	if strings.ContainsAny(s[last:], "{}") {
		return nil, errors.New("masque: malformed template")
	}
	if !seen["target_host"] || !seen["target_port"] {
		return nil, errors.New("masque: template needs both {target_host} and {target_port}")
	}
	t.pieces = append(t.pieces, piece{literal: s[last:]})
	re.WriteString(regexp.QuoteMeta(s[last:]))
	re.WriteString("$")
	p, err := regexp.Compile(re.String())
	if err != nil {
		return nil, err
	}
	t.pattern = p
	return t, nil
}

func escapeVar(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == '~':
			b.WriteByte(c)
		default:
			fmt.Fprintf(&b, "%%%02X", c)
		}
	}
	return b.String()
}

func (t *template) expand(dest addr.Addr) string {
	host := dest.Host()
	port := strconv.Itoa(int(dest.Port()))
	var b strings.Builder
	for _, p := range t.pieces {
		switch p.variable {
		case "":
			b.WriteString(p.literal)
		case "target_host":
			b.WriteString(escapeVar(host))
		default:
			b.WriteString(port)
		}
	}
	return b.String()
}

func (t *template) match(requestURI string) (addr.Addr, error) {
	m := t.pattern.FindStringSubmatch(requestURI)
	if m == nil {
		return addr.Addr{}, errors.New("path does not match template")
	}
	var host, port string
	for i, name := range t.pattern.SubexpNames() {
		switch name {
		case "target_host":
			host = m[i]
		case "target_port":
			port = m[i]
		}
	}
	host, err := url.PathUnescape(host)
	if err != nil {
		return addr.Addr{}, err
	}
	port, err = url.PathUnescape(port)
	if err != nil {
		return addr.Addr{}, err
	}
	host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil || n == 0 || host == "" {
		return addr.Addr{}, errors.New("bad target")
	}
	return addr.FromHost(host, uint16(n)), nil
}

func parseAuthority(s string) (addr.Addr, error) {
	a, err := addr.Parse(s)
	if err != nil || a.Port() == 0 || !a.IsValid() {
		return addr.Addr{}, fmt.Errorf("bad authority %q", s)
	}
	return a, nil
}

func netipParse(s string) (netip.AddrPort, error) { return netip.ParseAddrPort(s) }
