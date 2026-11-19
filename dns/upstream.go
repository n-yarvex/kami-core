package dns

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"time"

	"golang.org/x/net/dns/dnsmessage"

	"github.com/n-yarvex/kami-core/addr"
)

type DialFunc func(ctx context.Context, dest addr.Addr) (net.Conn, error)

type record struct {
	ip  netip.Addr
	ttl uint32
}

type answer struct {
	records []record
	nx      bool
}

type upstream interface {
	query(ctx context.Context, name string, qtype dnsmessage.Type) (answer, error)
}

func buildQuery(name string, qtype dnsmessage.Type) ([]byte, uint16, error) {
	n, err := dnsmessage.NewName(strings.TrimSuffix(name, ".") + ".")
	if err != nil {
		return nil, 0, fmt.Errorf("dns: bad name %q", name)
	}
	var id [2]byte
	if _, err := rand.Read(id[:]); err != nil {
		return nil, 0, err
	}
	qid := binary.BigEndian.Uint16(id[:])
	msg := dnsmessage.Message{
		Header:    dnsmessage.Header{ID: qid, RecursionDesired: true},
		Questions: []dnsmessage.Question{{Name: n, Type: qtype, Class: dnsmessage.ClassINET}},
	}
	raw, err := msg.Pack()
	return raw, qid, err
}

var errTruncated = errors.New("dns: truncated response")

func parseAnswer(raw []byte, id uint16, qtype dnsmessage.Type) (answer, error) {
	var p dnsmessage.Parser
	h, err := p.Start(raw)
	if err != nil {
		return answer{}, err
	}
	if h.ID != id || !h.Response {
		return answer{}, errors.New("dns: reply does not match the query")
	}
	if h.Truncated {
		return answer{}, errTruncated
	}
	switch h.RCode {
	case dnsmessage.RCodeSuccess:
	case dnsmessage.RCodeNameError:
		return answer{nx: true}, nil
	default:
		return answer{}, fmt.Errorf("dns: server answered %v", h.RCode)
	}
	if err := p.SkipAllQuestions(); err != nil {
		return answer{}, err
	}
	var out answer
	for {
		rh, err := p.AnswerHeader()
		if errors.Is(err, dnsmessage.ErrSectionDone) {
			break
		}
		if err != nil {
			return answer{}, err
		}
		switch {
		case rh.Type == dnsmessage.TypeA && qtype == dnsmessage.TypeA:
			r, err := p.AResource()
			if err != nil {
				return answer{}, err
			}
			out.records = append(out.records, record{netip.AddrFrom4(r.A), rh.TTL})
		case rh.Type == dnsmessage.TypeAAAA && qtype == dnsmessage.TypeAAAA:
			r, err := p.AAAAResource()
			if err != nil {
				return answer{}, err
			}
			out.records = append(out.records, record{netip.AddrFrom16(r.AAAA), rh.TTL})
		default:
			if err := p.SkipAnswer(); err != nil {
				return answer{}, err
			}
		}
	}
	return out, nil
}

type udpUpstream struct {
	server addr.Addr
	tcp    *tcpUpstream
}

func (u *udpUpstream) query(ctx context.Context, name string, qtype dnsmessage.Type) (answer, error) {
	raw, id, err := buildQuery(name, qtype)
	if err != nil {
		return answer{}, err
	}
	var last error
	for try := 0; try < 2; try++ {
		var d net.Dialer
		c, err := d.DialContext(ctx, "udp", u.server.String())
		if err != nil {
			return answer{}, err
		}
		ans, err := udpRound(ctx, c, raw, id, qtype)
		c.Close()
		if errors.Is(err, errTruncated) {
			return u.tcp.query(ctx, name, qtype)
		}
		if err == nil {
			return ans, nil
		}
		last = err
		if ctx.Err() != nil {
			break
		}
	}
	return answer{}, last
}

func udpRound(ctx context.Context, c net.Conn, raw []byte, id uint16, qtype dnsmessage.Type) (answer, error) {
	deadline := time.Now().Add(3 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	if _, err := c.Write(raw); err != nil {
		return answer{}, err
	}
	buf := make([]byte, 4096)
	for {
		n, err := c.Read(buf)
		if err != nil {
			return answer{}, err
		}
		ans, err := parseAnswer(buf[:n], id, qtype)
		if err != nil && !errors.Is(err, errTruncated) && strings.Contains(err.Error(), "does not match") {
			continue
		}
		return ans, err
	}
}

type tcpUpstream struct {
	server addr.Addr
	dial   DialFunc
	tls    *tls.Config
}

func (t *tcpUpstream) query(ctx context.Context, name string, qtype dnsmessage.Type) (answer, error) {
	raw, id, err := buildQuery(name, qtype)
	if err != nil {
		return answer{}, err
	}
	dctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	c, err := t.dial(dctx, t.server)
	if err != nil {
		return answer{}, err
	}
	defer c.Close()
	if t.tls != nil {
		cfg := t.tls.Clone()
		if cfg.ServerName == "" && !t.server.IsIP() {
			cfg.ServerName = t.server.Host()
		}
		tc := tls.Client(c, cfg)
		if err := tc.HandshakeContext(dctx); err != nil {
			return answer{}, err
		}
		c = tc
	}
	deadline := time.Now().Add(5 * time.Second)
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	c.SetDeadline(deadline)
	frame := make([]byte, 2+len(raw))
	binary.BigEndian.PutUint16(frame, uint16(len(raw)))
	copy(frame[2:], raw)
	if _, err := c.Write(frame); err != nil {
		return answer{}, err
	}
	var head [2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return answer{}, err
	}
	body := make([]byte, binary.BigEndian.Uint16(head[:]))
	if _, err := io.ReadFull(c, body); err != nil {
		return answer{}, err
	}
	return parseAnswer(body, id, qtype)
}

type httpsUpstream struct {
	url    string
	client *http.Client
}

func newHTTPSUpstream(rawURL string, dial DialFunc, cfg *tls.Config) (*httpsUpstream, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return nil, fmt.Errorf("dns: bad https server %q", rawURL)
	}
	if u.Path == "" {
		u.Path = "/dns-query"
	}
	tr := &http.Transport{
		DialContext: func(ctx context.Context, _, address string) (net.Conn, error) {
			a, err := addr.Parse(address)
			if err != nil {
				return nil, err
			}
			return dial(ctx, a)
		},
		TLSClientConfig:       cfg,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          4,
		IdleConnTimeout:       60 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ResponseHeaderTimeout: 5 * time.Second,
	}
	return &httpsUpstream{url: u.String(), client: &http.Client{Transport: tr, Timeout: 8 * time.Second}}, nil
}

func (h *httpsUpstream) query(ctx context.Context, name string, qtype dnsmessage.Type) (answer, error) {
	raw, id, err := buildQuery(name, qtype)
	if err != nil {
		return answer{}, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, h.url, bytes.NewReader(raw))
	if err != nil {
		return answer{}, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	resp, err := h.client.Do(req)
	if err != nil {
		return answer{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return answer{}, fmt.Errorf("dns: https server answered %s", resp.Status)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 65535))
	if err != nil {
		return answer{}, err
	}
	return parseAnswer(body, id, qtype)
}

type systemUpstream struct{}

func (systemUpstream) query(ctx context.Context, name string, qtype dnsmessage.Type) (answer, error) {
	network := "ip4"
	if qtype == dnsmessage.TypeAAAA {
		network = "ip6"
	}
	ips, err := net.DefaultResolver.LookupNetIP(ctx, network, name)
	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
		return answer{nx: true}, nil
	}
	if err != nil {
		return answer{}, err
	}
	out := answer{}
	for _, ip := range ips {
		out.records = append(out.records, record{ip.Unmap(), 60})
	}
	return out, nil
}

func parseServer(address string, dial DialFunc) (upstream, error) {
	if address == "local" {
		return systemUpstream{}, nil
	}
	scheme, rest, ok := strings.Cut(address, "://")
	if !ok {
		return nil, fmt.Errorf("dns: server %q needs a scheme (udp://, tcp://, tls://, https://, or \"local\")", address)
	}
	withPort := func(def string) (addr.Addr, error) {
		host := strings.TrimSuffix(rest, "/")
		if _, _, err := net.SplitHostPort(host); err != nil {
			host = net.JoinHostPort(strings.Trim(host, "[]"), def)
		}
		return addr.Parse(host)
	}
	switch scheme {
	case "udp":
		a, err := withPort("53")
		if err != nil {
			return nil, err
		}
		return &udpUpstream{server: a, tcp: &tcpUpstream{server: a, dial: dial}}, nil
	case "tcp":
		a, err := withPort("53")
		if err != nil {
			return nil, err
		}
		return &tcpUpstream{server: a, dial: dial}, nil
	case "tls":
		a, err := withPort("853")
		if err != nil {
			return nil, err
		}
		return &tcpUpstream{server: a, dial: dial, tls: &tls.Config{MinVersion: tls.VersionTLS12}}, nil
	case "https":
		return newHTTPSUpstream(address, dial, &tls.Config{MinVersion: tls.VersionTLS12})
	}
	return nil, fmt.Errorf("dns: unsupported scheme %q", scheme)
}
