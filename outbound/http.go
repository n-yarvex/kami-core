package outbound

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
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/tlsx"
)

const connectStepLimit = 15 * time.Second

func init() {
	adapter.RegisterOutbound("http", newHTTPOutbound)
}

type httpOutboundOptions struct {
	Server   string            `json:"server"`
	Username string            `json:"username"`
	Password string            `json:"password"`
	TLS      *tlsx.UClient     `json:"tls"`
	Headers  map[string]string `json:"headers"`
}

type httpOutbound struct {
	env     *adapter.OutboundEnv
	server  addr.Addr
	auth    string
	tls     *tlsx.UClient
	headers http.Header
}

func newHTTPOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o httpOutboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("http: bad server %q (want host:port)", o.Server)
	}
	if (o.Username == "") != (o.Password == "") {
		return nil, errors.New("http: username and password must be given together")
	}
	out := &httpOutbound{env: env, server: server, tls: o.TLS, headers: http.Header{}}
	if o.Username != "" {
		out.auth = "Basic " + base64.StdEncoding.EncodeToString([]byte(o.Username+":"+o.Password))
	}
	if o.TLS != nil {
		if err := o.TLS.Validate(server.Host()); err != nil {
			return nil, fmt.Errorf("http: %w", err)
		}
	}
	for k, v := range o.Headers {
		key := textproto.CanonicalMIMEHeaderKey(k)
		switch key {
		case "Host", "Proxy-Authorization", "Content-Length", "Transfer-Encoding", "Connection", "Proxy-Connection":
			return nil, fmt.Errorf("http: header %s is managed by kami and cannot be set", key)
		}
		if strings.ContainsAny(k, "\r\n:") || strings.ContainsAny(v, "\r\n") {
			return nil, fmt.Errorf("http: invalid header %q", k)
		}
		out.headers.Set(key, v)
	}
	return out, nil
}

func (h *httpOutbound) Tag() string       { return h.env.Tag }
func (h *httpOutbound) Type() string      { return "http" }
func (h *httpOutbound) SupportsUDP() bool { return false }
func (h *httpOutbound) Close() error      { return nil }

func (h *httpOutbound) OpenPacket(context.Context, addr.Addr) (adapter.PacketConn, error) {
	return nil, adapter.ErrNoUDP
}

type leftover struct {
	net.Conn
	r *bufio.Reader
}

func (l *leftover) Read(p []byte) (int, error) { return l.r.Read(p) }

func (l *leftover) CloseWrite() error {
	if cw, ok := l.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("no half close")
}

func (h *httpOutbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	conn, err := h.env.Dialer.DialStream(ctx, h.server)
	if err != nil {
		return nil, err
	}
	limit := time.Now().Add(connectStepLimit)
	if dl, ok := ctx.Deadline(); ok && dl.Before(limit) {
		limit = dl
	}
	conn.SetDeadline(limit)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	if h.tls != nil {
		tc, err := h.tls.Handshake(ctx, conn, h.server.Host(), []string{"http/1.1"})
		if err != nil {
			conn.Close()
			return nil, err
		}
		conn = tc
	}
	r, err := h.connect(conn, dest)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, err
	}
	conn.SetDeadline(time.Time{})
	if r.Buffered() == 0 {
		return conn, nil
	}
	return &leftover{Conn: conn, r: r}, nil
}

func (h *httpOutbound) connect(conn net.Conn, dest addr.Addr) (*bufio.Reader, error) {
	target := dest.String()
	var b strings.Builder
	fmt.Fprintf(&b, "CONNECT %s HTTP/1.1\r\nHost: %s\r\n", target, target)
	if h.auth != "" {
		fmt.Fprintf(&b, "Proxy-Authorization: %s\r\n", h.auth)
	}
	for k, vs := range h.headers {
		for _, v := range vs {
			fmt.Fprintf(&b, "%s: %s\r\n", k, v)
		}
	}
	b.WriteString("\r\n")
	if _, err := conn.Write([]byte(b.String())); err != nil {
		return nil, err
	}
	r := bufio.NewReaderSize(conn, 4096)
	resp, err := http.ReadResponse(r, &http.Request{Method: http.MethodConnect})
	if err != nil {
		return nil, fmt.Errorf("http: read CONNECT response: %w", err)
	}
	if resp.StatusCode/100 != 2 {
		switch resp.StatusCode {
		case http.StatusForbidden:
			return nil, fmt.Errorf("http: proxy answered %s: %w", resp.Status, ErrForbidden)
		case http.StatusProxyAuthRequired:
			return nil, errors.New("http: proxy requires authentication or rejected the credentials")
		}
		return nil, fmt.Errorf("http: proxy answered %s", resp.Status)
	}
	return r, nil
}
