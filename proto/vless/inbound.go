package vless

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/websocket"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterInbound("vless-ws", newWSInbound)
	adapter.RegisterInbound("vless-xudp", newXUDPInbound)
}

type User struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

type userTable map[UUID]string

func newUserTable(list []User) (userTable, error) {
	if len(list) == 0 {
		return nil, errors.New("at least one user is required")
	}
	t := make(userTable, len(list))
	names := map[string]bool{}
	for i, u := range list {
		id, err := ParseUUID(u.ID)
		if err != nil {
			return nil, fmt.Errorf("user %d: %w", i+1, err)
		}
		name := u.Name
		if name == "" {
			name = fmt.Sprintf("user%d", i+1)
		}
		if _, dup := t[id]; dup || names[name] {
			return nil, fmt.Errorf("user %q duplicates another user", name)
		}
		names[name] = true
		t[id] = name
	}
	return t, nil
}

type wsInboundOptions struct {
	Users            []User          `json:"users"`
	Path             string          `json:"path,omitempty"`
	TLS              *tlsx.Server    `json:"tls,omitempty"`
	HandshakeTimeout config.Duration `json:"handshake_timeout,omitempty"`
	XUDPHold         config.Duration `json:"xudp_hold,omitempty"`
	DisableUDP       bool            `json:"disable_udp,omitempty"`
}

type tracker struct {
	mu     sync.Mutex
	live   map[io.Closer]struct{}
	closed bool
}

func (t *tracker) add(c io.Closer) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return false
	}
	if t.live == nil {
		t.live = map[io.Closer]struct{}{}
	}
	t.live[c] = struct{}{}
	return true
}

func (t *tracker) remove(c io.Closer) {
	t.mu.Lock()
	delete(t.live, c)
	t.mu.Unlock()
}

func (t *tracker) closeAll() {
	t.mu.Lock()
	t.closed = true
	all := make([]io.Closer, 0, len(t.live))
	for c := range t.live {
		all = append(all, c)
	}
	t.mu.Unlock()
	for _, c := range all {
		c.Close()
	}
}

type serverConn struct {
	net.Conn
	r       io.Reader
	mu      sync.Mutex
	pending []byte
}

func (s *serverConn) Read(p []byte) (int, error) { return s.r.Read(p) }

func (s *serverConn) Write(p []byte) (int, error) {
	s.mu.Lock()
	hdr := s.pending
	s.pending = nil
	s.mu.Unlock()
	if hdr != nil {
		if _, err := s.Conn.Write(append(hdr, p...)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return s.Conn.Write(p)
}

func (s *serverConn) CloseWrite() error {
	s.mu.Lock()
	hdr := s.pending
	s.pending = nil
	s.mu.Unlock()
	if hdr != nil {
		s.Conn.Write(hdr)
	}
	if cw, ok := s.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("no half close")
}

type wsInbound struct {
	env     *adapter.InboundEnv
	users   userTable
	path    string
	tlsCfg  *tls.Config
	timeout time.Duration
	mux     *muxServer
	udp     bool
	up      websocket.Upgrader

	mu  sync.Mutex
	srv *http.Server
	tr  tracker
	wg  sync.WaitGroup
}

func newWSInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o wsInboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("vless-ws: %w", err)
	}
	users, err := newUserTable(o.Users)
	if err != nil {
		return nil, fmt.Errorf("vless-ws: %w", err)
	}
	in := &wsInbound{env: env, users: users, path: o.Path, timeout: o.HandshakeTimeout.Std(), udp: !o.DisableUDP}
	if in.path == "" {
		in.path = "/"
	}
	if !strings.HasPrefix(in.path, "/") {
		return nil, errors.New("vless-ws: path must start with /")
	}
	if in.timeout <= 0 {
		in.timeout = 15 * time.Second
	}
	hold := o.XUDPHold.Std()
	if hold <= 0 {
		hold = 60 * time.Second
	}
	in.mux = &muxServer{env: env, typ: "vless-ws", reg: newRegistry(), hold: hold}
	if o.TLS != nil {
		cfg, err := o.TLS.Config()
		if err != nil {
			return nil, fmt.Errorf("vless-ws: %w", err)
		}
		if len(cfg.NextProtos) == 0 {
			cfg.NextProtos = []string{"http/1.1"}
		}
		in.tlsCfg = cfg
	}
	in.up = websocket.Upgrader{
		HandshakeTimeout: 15 * time.Second,
		CheckOrigin:      func(*http.Request) bool { return true },
	}
	return in, nil
}

func (in *wsInbound) Tag() string  { return in.env.Tag }
func (in *wsInbound) Type() string { return "vless-ws" }

func (in *wsInbound) Start() error {
	ln, err := in.env.ListenTCP()
	if err != nil {
		return err
	}
	if in.tlsCfg != nil {
		ln = tls.NewListener(ln, in.tlsCfg)
	}
	srv := &http.Server{Handler: http.HandlerFunc(in.handle), ReadHeaderTimeout: in.timeout}
	in.mu.Lock()
	in.srv = srv
	in.mu.Unlock()
	in.wg.Add(1)
	go func() {
		defer in.wg.Done()
		srv.Serve(ln)
	}()
	return nil
}

func (in *wsInbound) Close() error {
	in.mu.Lock()
	srv := in.srv
	in.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
	in.tr.closeAll()
	in.wg.Wait()
	return nil
}

func (in *wsInbound) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != in.path || !websocket.IsWebSocketUpgrade(r) {
		http.NotFound(w, r)
		return
	}
	var early []byte
	respHdr := http.Header{}
	if v := r.Header.Get("Sec-WebSocket-Protocol"); v != "" && !strings.Contains(v, ",") {
		if b, err := base64.RawURLEncoding.DecodeString(v); err == nil && len(b) > 0 {
			early = b
			respHdr.Set("Sec-WebSocket-Protocol", v)
		}
	}
	c, err := in.up.Upgrade(w, r, respHdr)
	if err != nil {
		return
	}
	conn := newWSConn(c)
	if !in.tr.add(conn) {
		conn.Close()
		return
	}
	defer in.tr.remove(conn)
	defer conn.Close()
	br := bufio.NewReaderSize(io.MultiReader(bytes.NewReader(early), conn), 8192)
	serveVLESS(in.env, in.users, in.mux, in.timeout, in.udp, "vless-ws", conn, br)
}

func serveVLESS(env *adapter.InboundEnv, users userTable, mux *muxServer, timeout time.Duration, udp bool, typ string, conn net.Conn, br *bufio.Reader) {
	conn.SetReadDeadline(time.Now().Add(timeout))
	q, err := readRequest(br)
	if err != nil {
		env.Log.Debug(typ+" bad request", "from", conn.RemoteAddr().String(), "err", err)
		return
	}
	name, ok := users[q.id]
	if !ok {
		env.Log.Debug(typ+" unknown user", "from", conn.RemoteAddr().String())
		return
	}
	conn.SetReadDeadline(time.Time{})
	src := addr.FromNet(conn.RemoteAddr())
	switch q.cmd {
	case cmdTCP:
		sc := &serverConn{Conn: conn, r: br, pending: append([]byte(nil), responseHeader...)}
		env.Router.Stream(env.Ctx, sc, adapter.Metadata{
			Inbound:     env.Tag,
			InboundType: typ,
			User:        name,
			Network:     "tcp",
			Source:      src,
			Dest:        q.dest,
		})
	case cmdMux:
		if !udp {
			return
		}
		l := newStreamLink(conn, br, append([]byte(nil), responseHeader...))
		mux.run(l, name, q.id, src)
	default:
		env.Log.Debug(typ+" unsupported command", "cmd", q.cmd)
	}
}

type xudpInboundOptions struct {
	Users            []User          `json:"users"`
	Transport        string          `json:"transport,omitempty"`
	TLS              *tlsx.Server    `json:"tls,omitempty"`
	DTLS             *DTLSServer     `json:"dtls,omitempty"`
	HandshakeTimeout config.Duration `json:"handshake_timeout,omitempty"`
	IdleTimeout      config.Duration `json:"idle_timeout,omitempty"`
	XUDPHold         config.Duration `json:"xudp_hold,omitempty"`
}

type xudpInbound struct {
	env     *adapter.InboundEnv
	users   userTable
	dtls    bool
	tlsCfg  *tls.Config
	dcfg    *DTLSServer
	timeout time.Duration
	idle    time.Duration
	mux     *muxServer

	mu sync.Mutex
	ln net.Listener
	dl *dtlsListener
	tr tracker
	wg sync.WaitGroup
}

func newXUDPInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o xudpInboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("vless-xudp: %w", err)
	}
	users, err := newUserTable(o.Users)
	if err != nil {
		return nil, fmt.Errorf("vless-xudp: %w", err)
	}
	in := &xudpInbound{env: env, users: users, timeout: o.HandshakeTimeout.Std(), idle: o.IdleTimeout.Std()}
	if in.timeout <= 0 {
		in.timeout = 15 * time.Second
	}
	if in.idle <= 0 {
		in.idle = 2 * time.Minute
	}
	hold := o.XUDPHold.Std()
	if hold <= 0 {
		hold = 60 * time.Second
	}
	in.mux = &muxServer{env: env, typ: "vless-xudp", reg: newRegistry(), hold: hold}
	switch strings.ToLower(o.Transport) {
	case "", "tls":
		if o.DTLS != nil {
			return nil, errors.New("vless-xudp: dtls block needs transport \"dtls\"")
		}
		if o.TLS == nil {
			return nil, errors.New("vless-xudp: tls block is required")
		}
		cfg, err := o.TLS.Config()
		if err != nil {
			return nil, fmt.Errorf("vless-xudp: %w", err)
		}
		in.tlsCfg = cfg
	case "dtls":
		if o.TLS != nil {
			return nil, errors.New("vless-xudp: tls block does not apply to transport \"dtls\"")
		}
		if o.DTLS == nil {
			return nil, errors.New("vless-xudp: dtls block is required")
		}
		if _, err := o.DTLS.Config(); err != nil {
			return nil, fmt.Errorf("vless-xudp: %w", err)
		}
		in.dtls, in.dcfg = true, o.DTLS
	default:
		return nil, fmt.Errorf("vless-xudp: unknown transport %q (tls, dtls)", o.Transport)
	}
	return in, nil
}

func (in *xudpInbound) Tag() string  { return in.env.Tag }
func (in *xudpInbound) Type() string { return "vless-xudp" }

func (in *xudpInbound) Start() error {
	if in.dtls {
		cfg, err := in.dcfg.Config()
		if err != nil {
			return err
		}
		sock, err := in.env.ListenUDP()
		if err != nil {
			return err
		}
		dl := newDTLSListener(sock, cfg, in.dcfg.timeout(), in.serveDTLS)
		in.mu.Lock()
		in.dl = dl
		in.mu.Unlock()
		return nil
	}
	ln, err := in.env.ListenTCP()
	if err != nil {
		return err
	}
	ln = tls.NewListener(ln, in.tlsCfg)
	in.mu.Lock()
	in.ln = ln
	in.mu.Unlock()
	in.wg.Add(1)
	go in.acceptLoop(ln)
	return nil
}

func (in *xudpInbound) acceptLoop(ln net.Listener) {
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
		if !in.tr.add(conn) {
			conn.Close()
			continue
		}
		in.wg.Add(1)
		go func() {
			defer in.wg.Done()
			defer in.tr.remove(conn)
			defer conn.Close()
			br := bufio.NewReaderSize(conn, 8192)
			serveVLESS(in.env, in.users, in.mux, in.timeout, true, "vless-xudp", conn, br)
		}()
	}
}

func (in *xudpInbound) serveDTLS(conn net.Conn) {
	if !in.tr.add(conn) {
		return
	}
	defer in.tr.remove(conn)
	buf := make([]byte, 2048)
	conn.SetReadDeadline(time.Now().Add(in.timeout))
	n, err := conn.Read(buf)
	if err != nil || n < 2 || buf[0] != dgHello {
		return
	}
	br := bufio.NewReader(bytes.NewReader(buf[1:n]))
	q, err := readRequest(br)
	if err != nil || q.cmd != cmdMux {
		return
	}
	name, ok := in.users[q.id]
	if !ok {
		return
	}
	ack := append([]byte{dgHelloAck}, responseHeader...)
	if _, err := conn.Write(ack); err != nil {
		return
	}
	l := newDgramLink(conn)
	l.idle = in.idle
	l.onHello = func() { conn.Write(ack) }
	in.mux.run(l, name, q.id, addr.FromNet(conn.RemoteAddr()))
}

func (in *xudpInbound) Close() error {
	in.mu.Lock()
	ln, dl := in.ln, in.dl
	in.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	in.tr.closeAll()
	if dl != nil {
		dl.Close()
	}
	in.wg.Wait()
	return nil
}
