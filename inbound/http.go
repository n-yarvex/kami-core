package inbound

import (
	"bufio"
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

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/outbound"
)

func init() {
	adapter.RegisterInbound("http", func(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
		return newHTTP(env, raw)
	})
}

type httpInbound struct {
	base
	users users
}

func newHTTP(env *adapter.InboundEnv, raw json.RawMessage) (*httpInbound, error) {
	var o struct {
		Users []User `json:"users"`
	}
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	u, err := newUsers(o.Users)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	return &httpInbound{base: base{env: env, typ: "http"}, users: u}, nil
}

func (h *httpInbound) Start() error {
	return h.serve(func(conn net.Conn) {
		defer conn.Close()
		h.handle(wrap(conn))
	})
}

func (h *httpInbound) authorize(r *http.Request) (string, bool) {
	if h.users == nil {
		return "", true
	}
	hdr := r.Header.Get("Proxy-Authorization")
	scheme, payload, ok := strings.Cut(hdr, " ")
	if !ok || !strings.EqualFold(scheme, "basic") {
		return "", false
	}
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(payload))
	if err != nil {
		return "", false
	}
	name, pass, ok := strings.Cut(string(raw), ":")
	if !ok || !h.users.check(name, pass) {
		return "", false
	}
	return name, true
}

func status(w io.Writer, code int, extra string) {
	fmt.Fprintf(w, "HTTP/1.1 %d %s\r\n%sContent-Length: 0\r\nConnection: close\r\n\r\n", code, http.StatusText(code), extra)
}

func statusFor(err error) int {
	switch {
	case errors.Is(err, outbound.ErrForbidden):
		return http.StatusForbidden
	case strings.Contains(err.Error(), "timeout"), errors.Is(err, net.ErrClosed):
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}

var hopHeaders = []string{"Proxy-Connection", "Proxy-Authorization", "Proxy-Authenticate", "Connection", "Keep-Alive", "Te", "Trailer", "Upgrade"}

func (h *httpInbound) handle(c *buffered) {
	for {
		c.SetDeadline(time.Now().Add(handshakeTimeout))
		req, err := http.ReadRequest(c.r)
		if err != nil {
			return
		}
		user, ok := h.authorize(req)
		if !ok {
			status(c, http.StatusProxyAuthRequired, "Proxy-Authenticate: Basic realm=\"kami\"\r\n")
			return
		}
		if req.Method == http.MethodConnect {
			h.tunnel(c, req, user)
			return
		}
		if !h.forward(c, req, user) {
			return
		}
	}
}

func (h *httpInbound) tunnel(c *buffered, req *http.Request, user string) {
	dest, err := addr.Parse(req.Host)
	if err != nil || dest.Port() == 0 {
		status(c, http.StatusBadRequest, "")
		return
	}
	m := md(h.env, h.typ, "tcp", user, c, dest)
	var once sync.Once
	m.OnConnect = func(err error) {
		once.Do(func() {
			if err != nil {
				status(c, statusFor(err), "")
				return
			}
			c.SetDeadline(time.Time{})
			io.WriteString(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
		})
	}
	h.env.Router.Stream(h.env.Ctx, c.handoff(), m)
}

func (h *httpInbound) forward(c *buffered, req *http.Request, user string) bool {
	if req.URL.Host == "" || req.URL.Scheme != "http" {
		status(c, http.StatusBadRequest, "")
		return false
	}
	host := req.URL.Host
	if req.URL.Port() == "" {
		host = net.JoinHostPort(req.URL.Hostname(), "80")
	}
	dest, err := addr.Parse(host)
	if err != nil {
		status(c, http.StatusBadRequest, "")
		return false
	}
	client, server := net.Pipe()
	m := md(h.env, h.typ, "tcp", user, c, dest)
	var connectErr = make(chan error, 1)
	m.OnConnect = func(err error) { connectErr <- err }
	go func() {
		h.env.Router.Stream(h.env.Ctx, server, m)
		server.Close()
	}()
	if err := <-connectErr; err != nil {
		client.Close()
		status(c, statusFor(err), "")
		return false
	}
	defer client.Close()

	for _, k := range hopHeaders {
		req.Header.Del(k)
	}
	req.RequestURI = ""
	out := req.Clone(req.Context())
	out.Close = false
	if err := writeOrigin(client, out); err != nil {
		status(c, http.StatusBadGateway, "")
		return false
	}
	resp, err := http.ReadResponse(bufio.NewReader(client), req)
	if err != nil {
		status(c, http.StatusBadGateway, "")
		return false
	}
	defer resp.Body.Close()
	for _, k := range hopHeaders {
		resp.Header.Del(k)
	}
	keep := !req.Close && !resp.Close && (resp.ContentLength >= 0 || resp.TransferEncoding != nil || bodyless(resp.StatusCode))
	resp.Close = !keep
	c.SetDeadline(time.Time{})
	if err := resp.Write(c); err != nil {
		return false
	}
	return keep
}

func bodyless(code int) bool { return code/100 == 1 || code == 204 || code == 304 }

func writeOrigin(w io.Writer, r *http.Request) error {
	path := r.URL.RequestURI()
	if _, err := fmt.Fprintf(w, "%s %s HTTP/1.1\r\nHost: %s\r\n", r.Method, path, r.Host); err != nil {
		return err
	}
	r.Header.Del("Host")
	if r.ContentLength > 0 || len(r.TransferEncoding) > 0 {
		if len(r.TransferEncoding) > 0 {
			io.WriteString(w, "Transfer-Encoding: chunked\r\n")
		} else {
			fmt.Fprintf(w, "Content-Length: %d\r\n", r.ContentLength)
		}
	}
	r.Header.Del("Content-Length")
	r.Header.Del("Transfer-Encoding")
	if err := r.Header.Write(w); err != nil {
		return err
	}
	io.WriteString(w, "\r\n")
	if r.Body == nil || r.Body == http.NoBody {
		return nil
	}
	var body io.Writer = w
	if len(r.TransferEncoding) > 0 {
		cw := newChunked(w)
		defer cw.Close()
		body = cw
	}
	_, err := io.Copy(body, r.Body)
	return err
}
