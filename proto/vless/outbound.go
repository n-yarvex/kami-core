package vless

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/textproto"
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
	adapter.RegisterOutbound("vless-ws", newWSOutbound)
	adapter.RegisterOutbound("vless-xudp", newXUDPOutbound)
}

type xudpOutbound struct {
	env *adapter.OutboundEnv
	c   *xudpConnector
}

func newXUDPOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o xudpOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("vless-xudp: %w", err)
	}
	c, err := newXUDPConnector(env, o)
	if err != nil {
		return nil, err
	}
	return &xudpOutbound{env: env, c: c}, nil
}

func (o *xudpOutbound) Tag() string       { return o.env.Tag }
func (o *xudpOutbound) Type() string      { return "vless-xudp" }
func (o *xudpOutbound) SupportsUDP() bool { return true }
func (o *xudpOutbound) Close() error      { return nil }

func (o *xudpOutbound) DialStream(context.Context, addr.Addr) (net.Conn, error) {
	return nil, errors.New("vless-xudp carries udp only")
}

func (o *xudpOutbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	return o.c.open(ctx)
}

type wsOptions struct {
	Server          string            `json:"server"`
	ID              string            `json:"id"`
	Path            string            `json:"path,omitempty"`
	Host            string            `json:"host,omitempty"`
	Headers         map[string]string `json:"headers,omitempty"`
	TLS             *tlsx.UClient     `json:"tls,omitempty"`
	EarlyData       int               `json:"early_data,omitempty"`
	EarlyDataHeader string            `json:"early_data_header,omitempty"`
	PingInterval    *config.Duration  `json:"ping_interval,omitempty"`
	UDP             *bool             `json:"udp,omitempty"`
	KeepAlive       config.Duration   `json:"xudp_keepalive,omitempty"`
}

type wsOutbound struct {
	env      *adapter.OutboundEnv
	server   addr.Addr
	id       UUID
	path     string
	host     string
	headers  http.Header
	tls      *tlsx.UClient
	early    int
	earlyHdr string
	ping     time.Duration
	udp      bool
	xudp     *xudpConnector
	hdrTCP   func(dest addr.Addr) ([]byte, error)
}

func newWSOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o wsOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("vless-ws: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("vless-ws: bad server %q (want host:port)", o.Server)
	}
	id, err := ParseUUID(o.ID)
	if err != nil {
		return nil, fmt.Errorf("vless-ws: %w", err)
	}
	w := &wsOutbound{env: env, server: server, id: id, tls: o.TLS, headers: http.Header{}, ping: 30 * time.Second, udp: o.UDP == nil || *o.UDP}
	w.path = o.Path
	if w.path == "" {
		w.path = "/"
	}
	if !strings.HasPrefix(w.path, "/") {
		return nil, errors.New("vless-ws: path must start with /")
	}
	w.host = o.Host
	if w.host == "" {
		w.host = server.Host()
		if o.TLS != nil && o.TLS.ServerName != "" {
			w.host = o.TLS.ServerName
		}
	}
	if o.TLS != nil {
		if err := o.TLS.Validate(server.Host()); err != nil {
			return nil, fmt.Errorf("vless-ws: %w", err)
		}
	}
	for k, v := range o.Headers {
		key := textproto.CanonicalMIMEHeaderKey(k)
		switch key {
		case "Host", "Upgrade", "Connection", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions", "Sec-Websocket-Protocol":
			return nil, fmt.Errorf("vless-ws: header %s is managed by kami and cannot be set", key)
		}
		if strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("vless-ws: invalid header %q", k)
		}
		w.headers.Set(key, v)
	}
	if o.EarlyData < 0 || o.EarlyData > 8192 {
		return nil, errors.New("vless-ws: early_data must be between 0 and 8192")
	}
	w.early = o.EarlyData
	w.earlyHdr = o.EarlyDataHeader
	if w.earlyHdr == "" {
		w.earlyHdr = "Sec-WebSocket-Protocol"
	}
	w.earlyHdr = textproto.CanonicalMIMEHeaderKey(w.earlyHdr)
	if w.earlyHdr != "Sec-Websocket-Protocol" {
		switch w.earlyHdr {
		case "Host", "Upgrade", "Connection", "Sec-Websocket-Key", "Sec-Websocket-Version", "Sec-Websocket-Extensions":
			return nil, fmt.Errorf("vless-ws: early_data_header %s is not allowed", w.earlyHdr)
		}
		if w.headers.Get(w.earlyHdr) != "" {
			return nil, fmt.Errorf("vless-ws: early_data_header %s collides with headers", w.earlyHdr)
		}
	}
	if o.PingInterval != nil {
		w.ping = o.PingInterval.Std()
	}
	hdr, err := appendRequest(nil, request{id: id, cmd: cmdMux})
	if err != nil {
		return nil, err
	}
	w.xudp = &xudpConnector{env: env, server: server, id: id, retry: true, header: hdr, keepalive: o.KeepAlive.Std()}
	if w.xudp.keepalive <= 0 {
		w.xudp.keepalive = 20 * time.Second
	}
	w.xudp.custom = w.dialMux
	return w, nil
}

func (w *wsOutbound) Tag() string       { return w.env.Tag }
func (w *wsOutbound) Type() string      { return "vless-ws" }
func (w *wsOutbound) SupportsUDP() bool { return w.udp }
func (w *wsOutbound) Close() error      { return nil }

func (w *wsOutbound) dialWS(ctx context.Context, early []byte) (*wsConn, error) {
	scheme := "ws"
	if w.tls != nil {
		scheme = "wss"
	}
	hdr := http.Header{}
	for k, v := range w.headers {
		hdr[k] = v
	}
	hdr.Set("Host", w.host)
	if len(early) > 0 {
		hdr.Set(w.earlyHdr, base64.RawURLEncoding.EncodeToString(early))
	}
	dial := func(ctx context.Context, _, _ string) (net.Conn, error) {
		return w.env.Dialer.DialStream(ctx, w.server)
	}
	d := websocket.Dialer{
		HandshakeTimeout:  15 * time.Second,
		NetDialContext:    dial,
		EnableCompression: false,
	}
	if w.tls != nil {
		d.NetDialTLSContext = func(ctx context.Context, network, address string) (net.Conn, error) {
			raw, err := dial(ctx, network, address)
			if err != nil {
				return nil, err
			}
			hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
			defer cancel()
			conn, err := w.tls.Handshake(hctx, raw, w.server.Host(), []string{"http/1.1"})
			if err != nil {
				raw.Close()
				return nil, err
			}
			return conn, nil
		}
	}
	url := fmt.Sprintf("%s://%s%s", scheme, w.server.String(), w.path)
	c, resp, err := d.DialContext(ctx, url, hdr)
	if err != nil {
		if resp != nil {
			return nil, fmt.Errorf("vless-ws: upgrade failed: %s", resp.Status)
		}
		return nil, err
	}
	wc := newWSConn(c)
	if w.ping > 0 {
		go wc.keepalive(w.ping, closedChan(c))
	}
	return wc, nil
}

func closedChan(c *websocket.Conn) <-chan struct{} {
	ch := make(chan struct{})
	prev := c.CloseHandler()
	c.SetCloseHandler(func(code int, text string) error {
		select {
		case <-ch:
		default:
			close(ch)
		}
		return prev(code, text)
	})
	return ch
}

func (w *wsOutbound) dialMux(ctx context.Context) (link, error) {
	conn, err := w.dialWS(ctx, nil)
	if err != nil {
		return nil, err
	}
	l := newStreamLink(conn, nil, append([]byte(nil), w.xudp.header...))
	if err := l.flushHeader(); err != nil {
		conn.Close()
		return nil, err
	}
	return l, nil
}

func (w *wsOutbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	if !w.udp {
		return nil, adapter.ErrNoUDP
	}
	return w.xudp.open(ctx)
}

func (w *wsOutbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	hdr, err := appendRequest(nil, request{id: w.id, cmd: cmdTCP, dest: dest})
	if err != nil {
		return nil, err
	}
	c := &vlessClientConn{w: w, hdr: hdr, ctx: context.WithoutCancel(ctx)}
	if w.early > 0 {
		return c, nil
	}
	conn, err := w.dialWS(ctx, nil)
	if err != nil {
		return nil, err
	}
	c.conn = conn
	c.br = bufio.NewReaderSize(conn, 8192)
	return c, nil
}

type vlessClientConn struct {
	w   *wsOutbound
	ctx context.Context
	hdr []byte

	rmu    sync.Mutex
	mu     sync.Mutex
	conn   *wsConn
	br     *bufio.Reader
	closed bool
	rdl    time.Time
	wdl    time.Time
	hdrIn  bool
}

func (c *vlessClientConn) connectLocked(first []byte) error {
	if c.closed {
		return net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(c.ctx, 20*time.Second)
	defer cancel()
	conn, err := c.w.dialWS(ctx, first)
	if err != nil {
		return err
	}
	if !c.rdl.IsZero() {
		conn.SetReadDeadline(c.rdl)
	}
	if !c.wdl.IsZero() {
		conn.SetWriteDeadline(c.wdl)
	}
	c.conn = conn
	c.br = bufio.NewReaderSize(conn, 8192)
	return nil
}

func (c *vlessClientConn) Write(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if c.conn == nil {
		data := append(append([]byte(nil), c.hdr...), p...)
		n := min(len(data), c.w.early)
		if err := c.connectLocked(data[:n]); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		c.hdr = nil
		conn := c.conn
		c.mu.Unlock()
		if n < len(data) {
			if _, err := conn.Write(data[n:]); err != nil {
				return 0, err
			}
		}
		return len(p), nil
	}
	conn, hdr := c.conn, c.hdr
	c.hdr = nil
	c.mu.Unlock()
	if hdr != nil {
		if _, err := conn.Write(append(hdr, p...)); err != nil {
			return 0, err
		}
		return len(p), nil
	}
	return conn.Write(p)
}

func (c *vlessClientConn) Read(p []byte) (int, error) {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return 0, net.ErrClosed
	}
	if c.conn == nil {
		if err := c.connectLocked(c.hdr); err != nil {
			c.mu.Unlock()
			return 0, err
		}
		c.hdr = nil
	} else if c.hdr != nil {
		hdr := c.hdr
		c.hdr = nil
		if _, err := c.conn.Write(hdr); err != nil {
			c.mu.Unlock()
			return 0, err
		}
	}
	br := c.br
	c.mu.Unlock()
	c.rmu.Lock()
	defer c.rmu.Unlock()
	if !c.hdrIn {
		if err := skipResponseHeader(br); err != nil {
			return 0, err
		}
		c.hdrIn = true
	}
	return br.Read(p)
}

func (c *vlessClientConn) Close() error {
	c.mu.Lock()
	c.closed = true
	conn := c.conn
	c.mu.Unlock()
	if conn != nil {
		return conn.Close()
	}
	return nil
}

func (c *vlessClientConn) CloseWrite() error {
	c.mu.Lock()
	conn := c.conn
	c.mu.Unlock()
	if conn == nil {
		return errors.New("not connected")
	}
	return conn.CloseWrite()
}

func (c *vlessClientConn) LocalAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.LocalAddr()
	}
	return &net.TCPAddr{}
}

func (c *vlessClientConn) RemoteAddr() net.Addr {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.conn != nil {
		return c.conn.RemoteAddr()
	}
	return &net.TCPAddr{}
}

func (c *vlessClientConn) SetDeadline(t time.Time) error {
	c.SetReadDeadline(t)
	return c.SetWriteDeadline(t)
}

func (c *vlessClientConn) SetReadDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rdl = t
	if c.conn != nil {
		return c.conn.SetReadDeadline(t)
	}
	return nil
}

func (c *vlessClientConn) SetWriteDeadline(t time.Time) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.wdl = t
	if c.conn != nil {
		return c.conn.SetWriteDeadline(t)
	}
	return nil
}
