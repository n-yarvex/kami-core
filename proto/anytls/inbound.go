package anytls

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

const quietLimit = 10 * time.Minute

func init() {
	adapter.RegisterInbound("anytls", newInbound)
}

type schemeText string

func (t *schemeText) UnmarshalJSON(raw []byte) error {
	var one string
	if json.Unmarshal(raw, &one) == nil {
		*t = schemeText(one)
		return nil
	}
	var lines []string
	if err := json.Unmarshal(raw, &lines); err != nil {
		return errors.New("padding_scheme must be a string or a list of lines")
	}
	*t = schemeText(strings.Join(lines, "\n"))
	return nil
}

type userOption struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type inboundOptions struct {
	Users            []userOption    `json:"users"`
	Password         string          `json:"password"`
	TLS              tlsx.Server     `json:"tls"`
	PaddingScheme    schemeText      `json:"padding_scheme"`
	HandshakeTimeout config.Duration `json:"handshake_timeout"`
	DisableUDP       bool            `json:"disable_udp"`
}

type account struct {
	name string
	hash [sha256.Size]byte
}

type inbound struct {
	env     *adapter.InboundEnv
	tls     *tls.Config
	users   []account
	shape   *scheme
	timeout time.Duration
	udp     bool

	mu     sync.Mutex
	ln     net.Listener
	live   map[net.Conn]struct{}
	muxes  map[*mux]struct{}
	closed bool
	stop   chan struct{}
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	var users []account
	seen := map[string]bool{}
	add := func(name, password string) error {
		if password == "" {
			return errors.New("anytls: user password must not be empty")
		}
		if seen[name] {
			return fmt.Errorf("anytls: duplicate user %q", name)
		}
		seen[name] = true
		users = append(users, account{name: name, hash: sha256.Sum256([]byte(password))})
		return nil
	}
	if o.Password != "" {
		if err := add("default", o.Password); err != nil {
			return nil, err
		}
	}
	for i, u := range o.Users {
		if u.Name == "" {
			u.Name = fmt.Sprintf("user%d", i+1)
		}
		if err := add(u.Name, u.Password); err != nil {
			return nil, err
		}
	}
	if len(users) == 0 {
		return nil, errors.New("anytls: password or users is required")
	}
	shape := builtinScheme
	if o.PaddingScheme != "" {
		var err error
		if shape, err = parseScheme(string(o.PaddingScheme)); err != nil {
			return nil, fmt.Errorf("anytls: %w", err)
		}
	}
	cfg, err := o.TLS.Config()
	if err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	timeout := o.HandshakeTimeout.Std()
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &inbound{
		env: env, tls: cfg, users: users, shape: shape, timeout: timeout, udp: !o.DisableUDP,
		live: map[net.Conn]struct{}{}, muxes: map[*mux]struct{}{}, stop: make(chan struct{}),
	}, nil
}

func (in *inbound) Tag() string  { return in.env.Tag }
func (in *inbound) Type() string { return "anytls" }

func (in *inbound) Start() error {
	ln, err := in.env.ListenTCP()
	if err != nil {
		return err
	}
	in.mu.Lock()
	in.ln = ln
	in.mu.Unlock()
	in.wg.Add(2)
	go in.reap()
	go in.loop(ln)
	return nil
}

func (in *inbound) loop(ln net.Listener) {
	defer in.wg.Done()
	var pause time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			pause = min(max(pause*2, 5*time.Millisecond), time.Second)
			time.Sleep(pause)
			continue
		}
		pause = 0
		if !in.hold(conn) {
			conn.Close()
			continue
		}
		in.wg.Add(1)
		go func() {
			defer in.wg.Done()
			defer in.release(conn)
			in.session(conn)
		}()
	}
}

func (in *inbound) hold(c net.Conn) bool {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.closed {
		return false
	}
	in.live[c] = struct{}{}
	return true
}

func (in *inbound) release(c net.Conn) {
	in.mu.Lock()
	delete(in.live, c)
	in.mu.Unlock()
	c.Close()
}

func (in *inbound) reap() {
	defer in.wg.Done()
	tick := time.NewTicker(time.Minute)
	defer tick.Stop()
	for {
		select {
		case <-in.stop:
			return
		case <-tick.C:
			var quiet []*mux
			in.mu.Lock()
			for m := range in.muxes {
				if m.quiet(quietLimit) {
					quiet = append(quiet, m)
				}
			}
			in.mu.Unlock()
			for _, m := range quiet {
				m.kill()
			}
		}
	}
}

func (in *inbound) authenticate(c net.Conn) (string, bool) {
	c.SetReadDeadline(time.Now().Add(in.timeout))
	defer c.SetReadDeadline(time.Time{})
	var head [sha256.Size + 2]byte
	if _, err := io.ReadFull(c, head[:]); err != nil {
		return "", false
	}
	name, ok := "", 0
	for i := range in.users {
		ok |= subtle.ConstantTimeCompare(in.users[i].hash[:], head[:sha256.Size])
		if subtle.ConstantTimeCompare(in.users[i].hash[:], head[:sha256.Size]) == 1 {
			name = in.users[i].name
		}
	}
	pad := int64(binary.BigEndian.Uint16(head[sha256.Size:]))
	if _, err := io.CopyN(io.Discard, c, pad); err != nil {
		return "", false
	}
	return name, ok == 1
}

func (in *inbound) session(raw net.Conn) {
	raw.SetDeadline(time.Now().Add(in.timeout))
	tc := tls.Server(raw, in.tls)
	if err := tc.Handshake(); err != nil {
		in.env.Log.Debug("anytls tls handshake failed", "from", raw.RemoteAddr().String(), "err", err)
		return
	}
	raw.SetDeadline(time.Time{})
	user, ok := in.authenticate(tc)
	if !ok {
		in.env.Log.Debug("anytls auth failed", "from", raw.RemoteAddr().String())
		return
	}
	src := addr.FromNet(raw.RemoteAddr())
	m := newMux(tc, false, in.shape, muxHooks{
		accept: func(s *stream) { in.serveStream(s, user, src) },
	})
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return
	}
	in.muxes[m] = struct{}{}
	in.mu.Unlock()
	defer func() {
		in.mu.Lock()
		delete(in.muxes, m)
		in.mu.Unlock()
	}()
	m.serve()
}

type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *buffered) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("half close unsupported")
}

func (in *inbound) serveStream(s *stream, user string, src addr.Addr) {
	s.SetReadDeadline(time.Now().Add(in.timeout))
	r := bufio.NewReaderSize(s, 4096)
	dest, err := addr.ReadSocks(r)
	if err != nil {
		s.Close()
		return
	}
	md := adapter.Metadata{
		Inbound:     in.env.Tag,
		InboundType: "anytls",
		User:        user,
		Source:      src,
	}
	ack := func(err error) {
		if s.mux.peerVer.Load() < 2 {
			return
		}
		var body []byte
		if err != nil {
			body = []byte(err.Error())
		}
		s.mux.control(opSynAck, s.id, body)
	}
	if dest.IsDomain() && dest.Host() == uotHost {
		in.serveDatagrams(s, r, md, ack)
		return
	}
	s.SetReadDeadline(time.Time{})
	md.Network, md.Dest = "tcp", dest
	var once sync.Once
	md.OnConnect = func(err error) { once.Do(func() { ack(err) }) }
	var conn net.Conn = s
	if r.Buffered() > 0 {
		conn = &buffered{Conn: s, r: r}
	}
	in.env.Router.Stream(in.env.Ctx, conn, md)
}

func (in *inbound) serveDatagrams(s *stream, r *bufio.Reader, md adapter.Metadata, ack func(error)) {
	if !in.udp {
		ack(errors.New("udp is disabled"))
		s.Close()
		return
	}
	flag, err := r.ReadByte()
	if err != nil {
		s.Close()
		return
	}
	fixed, err := addr.ReadSocks(r)
	if err != nil {
		s.Close()
		return
	}
	s.SetReadDeadline(time.Time{})
	ack(nil)
	md.Network = "udp"
	pc := newUoTConn(s, r, flag == 1, fixed)
	in.env.Router.Packet(in.env.Ctx, pc, md)
	s.Close()
}

func (in *inbound) Close() error {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return nil
	}
	in.closed = true
	close(in.stop)
	ln := in.ln
	conns := make([]net.Conn, 0, len(in.live))
	for c := range in.live {
		conns = append(conns, c)
	}
	in.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.Close()
	}
	in.wg.Wait()
	return nil
}
