package outbound

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
)

const (
	defaultProbeURL = "https://www.gstatic.com/generate_204"
	probeTimeout    = 5 * time.Second
)

func init() {
	adapter.RegisterOutbound("selector", newSelector)
	adapter.RegisterOutbound("urltest", func(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
		return newTester(env, raw, false)
	})
	adapter.RegisterOutbound("fallback", func(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
		return newTester(env, raw, true)
	})
}

type members struct {
	env  *adapter.OutboundEnv
	tags []string
	list []adapter.Outbound
}

func (m *members) resolve() error {
	m.list = m.list[:0]
	for _, tag := range m.tags {
		ob, ok := m.env.Lookup(tag)
		if !ok {
			return fmt.Errorf("%s: member %q does not exist", m.env.Tag, tag)
		}
		if tag == m.env.Tag {
			return fmt.Errorf("%s: a group cannot contain itself", tag)
		}
		m.list = append(m.list, ob)
	}
	return nil
}

type selector struct {
	members
	mu      sync.RWMutex
	current int
	pick    string
}

func newSelector(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o struct {
		Outbounds []string `json:"outbounds"`
		Default   string   `json:"default"`
	}
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("selector: %w", err)
	}
	if len(o.Outbounds) == 0 {
		return nil, errors.New("selector: outbounds is empty")
	}
	return &selector{members: members{env: env, tags: o.Outbounds}, pick: o.Default}, nil
}

func (s *selector) Start() error {
	if err := s.resolve(); err != nil {
		return err
	}
	if s.pick != "" {
		return s.Select(s.pick)
	}
	return nil
}

func (s *selector) Tag() string  { return s.env.Tag }
func (s *selector) Type() string { return "selector" }
func (s *selector) Close() error { return nil }

func (s *selector) Members() []adapter.Outbound { return s.list }

func (s *selector) Select(tag string) error {
	for i, ob := range s.list {
		if ob.Tag() == tag {
			s.mu.Lock()
			s.current = i
			s.mu.Unlock()
			return nil
		}
	}
	return fmt.Errorf("selector %s: no member %q", s.env.Tag, tag)
}

func (s *selector) now() adapter.Outbound {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.list[s.current]
}

func (s *selector) Now() string { return s.now().Tag() }

func (s *selector) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	return s.now().DialStream(ctx, dest)
}

func (s *selector) OpenPacket(ctx context.Context, dest addr.Addr) (adapter.PacketConn, error) {
	return s.now().OpenPacket(ctx, dest)
}

type tester struct {
	members
	probeURL  string
	interval  time.Duration
	tolerance time.Duration
	ordered   bool

	mu      sync.RWMutex
	current int
	rtt     []time.Duration
	failed  []bool

	kick   chan struct{}
	stop   chan struct{}
	done   chan struct{}
	closed sync.Once
	prober func(ctx context.Context, ob adapter.Outbound) (time.Duration, error)
}

func newTester(env *adapter.OutboundEnv, raw json.RawMessage, ordered bool) (adapter.Outbound, error) {
	var o struct {
		Outbounds []string        `json:"outbounds"`
		URL       string          `json:"url"`
		Interval  config.Duration `json:"interval"`
		Tolerance config.Duration `json:"tolerance"`
	}
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("urltest: %w", err)
	}
	if len(o.Outbounds) == 0 {
		return nil, errors.New("urltest: outbounds is empty")
	}
	t := &tester{
		members:   members{env: env, tags: o.Outbounds},
		probeURL:  o.URL,
		interval:  o.Interval.Std(),
		tolerance: o.Tolerance.Std(),
		ordered:   ordered,
		kick:      make(chan struct{}, 1),
		stop:      make(chan struct{}),
		done:      make(chan struct{}),
	}
	if t.probeURL == "" {
		t.probeURL = defaultProbeURL
	}
	if t.interval <= 0 {
		t.interval = 3 * time.Minute
	}
	if t.tolerance <= 0 {
		t.tolerance = 50 * time.Millisecond
	}
	u, err := url.Parse(t.probeURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("urltest: bad url %q", t.probeURL)
	}
	t.prober = t.probe
	return t, nil
}

func (t *tester) Start() error {
	if err := t.resolve(); err != nil {
		return err
	}
	t.rtt = make([]time.Duration, len(t.list))
	t.failed = make([]bool, len(t.list))
	go t.loop()
	t.recheck()
	return nil
}

func (t *tester) Tag() string {
	return t.env.Tag
}

func (t *tester) Type() string {
	if t.ordered {
		return "fallback"
	}
	return "urltest"
}

func (t *tester) Members() []adapter.Outbound { return t.list }

func (t *tester) Close() error {
	t.closed.Do(func() { close(t.stop) })
	select {
	case <-t.done:
	case <-time.After(time.Second):
	}
	return nil
}

func (t *tester) recheck() {
	select {
	case t.kick <- struct{}{}:
	default:
	}
}

func (t *tester) loop() {
	defer close(t.done)
	tick := time.NewTicker(t.interval)
	defer tick.Stop()
	for {
		select {
		case <-t.stop:
			return
		case <-tick.C:
		case <-t.kick:
		}
		t.runOnce()
	}
}

func (t *tester) runOnce() {
	var wg sync.WaitGroup
	rtt := make([]time.Duration, len(t.list))
	failed := make([]bool, len(t.list))
	for i, ob := range t.list {
		if _, isGroup := ob.(adapter.Group); isGroup {
			continue
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			ctx, cancel := context.WithTimeout(context.Background(), probeTimeout)
			defer cancel()
			d, err := t.prober(ctx, ob)
			if err != nil {
				failed[i] = true
				return
			}
			rtt[i] = d
		}()
	}
	wg.Wait()
	t.mu.Lock()
	defer t.mu.Unlock()
	t.rtt, t.failed = rtt, failed
	best := -1
	for i := range t.list {
		if failed[i] {
			continue
		}
		if t.ordered {
			best = i
			break
		}
		if best < 0 || rtt[i] < rtt[best] {
			best = i
		}
	}
	if best < 0 {
		return
	}
	cur := t.current
	if !t.ordered && !failed[cur] && rtt[cur] <= rtt[best]+t.tolerance {
		return
	}
	if t.current != best {
		t.env.Log.Info("group switched", "group", t.env.Tag, "to", t.list[best].Tag())
	}
	t.current = best
}

func (t *tester) probe(ctx context.Context, ob adapter.Outbound) (time.Duration, error) {
	u, _ := url.Parse(t.probeURL)
	port := u.Port()
	if port == "" {
		port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
	}
	dest, err := addr.Parse(net.JoinHostPort(u.Hostname(), port))
	if err != nil {
		return 0, err
	}
	start := time.Now()
	conn, err := ob.DialStream(ctx, dest)
	if err != nil {
		return 0, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(probeTimeout))
	if u.Scheme == "https" {
		tc := tls.Client(conn, &tls.Config{ServerName: u.Hostname()})
		if err := tc.HandshakeContext(ctx); err != nil {
			return 0, err
		}
		conn = tc
	}
	path := u.RequestURI()
	if _, err := fmt.Fprintf(conn, "GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: kami\r\nConnection: close\r\n\r\n", path, u.Host); err != nil {
		return 0, err
	}
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		return 0, err
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		return 0, errors.New(strings.TrimSpace(resp.Status))
	}
	return time.Since(start), nil
}

func (t *tester) now() adapter.Outbound {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.list[t.current]
}

func (t *tester) Now() string { return t.now().Tag() }

func (t *tester) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	c, err := t.now().DialStream(ctx, dest)
	if err != nil {
		t.recheck()
	}
	return c, err
}

func (t *tester) OpenPacket(ctx context.Context, dest addr.Addr) (adapter.PacketConn, error) {
	pc, err := t.now().OpenPacket(ctx, dest)
	if err != nil {
		t.recheck()
	}
	return pc, err
}
