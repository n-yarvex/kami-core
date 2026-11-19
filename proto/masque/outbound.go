package masque

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterOutbound("masque", newOutbound)
}

type authOptions struct {
	User     string `json:"user"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type outboundOptions struct {
	transportOptions
	Server      string            `json:"server"`
	Authority   string            `json:"authority"`
	Auth        authOptions       `json:"auth"`
	Headers     map[string]string `json:"headers"`
	TLS         tlsx.Client       `json:"tls"`
	UDPTemplate string            `json:"udp_template"`
	UDPTimeout  config.Duration   `json:"udp_timeout"`
	DisableUDP  bool              `json:"disable_udp"`
	NoDatagram  bool              `json:"no_datagram"`
}

type StatusError struct {
	Code int
	Kind error
}

var (
	ErrAuthRequired = errors.New("masque: proxy requires authentication")
	ErrForbidden    = errors.New("masque: proxy refused the request")
	ErrUpstream     = errors.New("masque: proxy could not reach the target")
)

func (e *StatusError) Error() string {
	return fmt.Sprintf("masque: proxy answered %d (%v)", e.Code, e.Kind)
}

func (e *StatusError) Unwrap() error { return e.Kind }

func statusError(code int) error {
	switch code {
	case http.StatusProxyAuthRequired:
		return &StatusError{code, ErrAuthRequired}
	case http.StatusForbidden:
		return &StatusError{code, ErrForbidden}
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return &StatusError{code, ErrUpstream}
	}
	return &StatusError{code, errors.New("unexpected status")}
}

type outbound struct {
	env       *adapter.OutboundEnv
	mgr       *manager
	tpl       *template
	authority string
	headers   http.Header
	nat       time.Duration
	udp       bool
	noDG      bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("masque: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("masque: bad server %q (want host:port)", o.Server)
	}
	tpl, err := compileTemplate(o.UDPTemplate)
	if err != nil {
		return nil, err
	}
	tcfg, err := o.TLS.Config(server.Host())
	if err != nil {
		return nil, fmt.Errorf("masque: %w", err)
	}
	tcfg = forceH3(tcfg)
	qcfg, err := o.quicConfig(16)
	if err != nil {
		return nil, err
	}
	hdr := http.Header{}
	for k, v := range o.Headers {
		hdr.Set(k, v)
	}
	switch {
	case o.Auth.Token != "" && (o.Auth.User != "" || o.Auth.Password != ""):
		return nil, errors.New("masque: auth takes either token or user/password")
	case o.Auth.Token != "":
		hdr.Set("Proxy-Authorization", bearerValue(o.Auth.Token))
	case o.Auth.User != "":
		hdr.Set("Proxy-Authorization", basicValue(o.Auth.User, o.Auth.Password))
	}
	authority := o.Authority
	if authority == "" {
		authority = server.String()
	}
	ob := &outbound{env: env, tpl: tpl, authority: authority, headers: hdr, nat: o.UDPTimeout.Std(), udp: !o.DisableUDP, noDG: o.NoDatagram}
	if ob.nat <= 0 {
		ob.nat = flowNAT
	}
	ob.mgr = &manager{establish: func(ctx context.Context) (*session, error) {
		return ob.dial(ctx, server, tcfg, qcfg)
	}}
	return ob, nil
}

func (o *outbound) dial(ctx context.Context, server addr.Addr, tcfg *tls.Config, qcfg *quic.Config) (*session, error) {
	var remote *net.UDPAddr
	if server.IsIP() {
		remote = server.UDPAddr()
	} else {
		ips, err := o.env.Resolver.Lookup(ctx, server.Host())
		if err != nil {
			return nil, err
		}
		if len(ips) == 0 {
			return nil, fmt.Errorf("masque: no address for %s", server.Host())
		}
		pick := ips[0]
		for _, ip := range ips {
			if ip.Is4() {
				pick = ip
				break
			}
		}
		remote = net.UDPAddrFromAddrPort(netip.AddrPortFrom(pick, server.Port()))
	}
	pc, err := o.env.Dialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	tr := &quic.Transport{Conn: pc}
	conn, err := tr.Dial(ctx, remote, tcfg, qcfg)
	if err != nil {
		tr.Close()
		pc.Close()
		return nil, err
	}
	h3 := &http3.Transport{EnableDatagrams: true}
	cc := h3.NewClientConn(conn)
	s := &session{conn: conn, cc: cc, tr: tr, pc: pc}
	wait := time.NewTimer(settingsWait)
	defer wait.Stop()
	select {
	case <-cc.ReceivedSettings():
	case <-wait.C:
		s.shutdown()
		return nil, errors.New("masque: timed out waiting for HTTP/3 settings")
	case <-ctx.Done():
		s.shutdown()
		return nil, ctx.Err()
	}
	st := cc.Settings()
	s.ext = st.EnableExtendedConnect
	s.dg = st.EnableDatagrams && conn.ConnectionState().SupportsDatagrams.Remote
	go func() {
		<-conn.Context().Done()
		tr.Close()
		pc.Close()
	}()
	return s, nil
}

func (o *outbound) Tag() string       { return o.env.Tag }
func (o *outbound) Type() string      { return "masque" }
func (o *outbound) SupportsUDP() bool { return o.udp }
func (o *outbound) Close() error      { o.mgr.shutdown(); return nil }

func (o *outbound) request(method, proto string, u *url.URL) *http.Request {
	r := &http.Request{Method: method, Proto: proto, Host: o.authority, URL: u, Header: o.headers.Clone()}
	if r.Header == nil {
		r.Header = http.Header{}
	}
	return r
}

func finish(rs *http3.RequestStream) (*http.Response, error) {
	resp, err := rs.ReadResponse()
	if err != nil {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, statusError(resp.StatusCode)
	}
	return resp, nil
}

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	rs, s, err := o.mgr.open(ctx)
	if err != nil {
		return nil, err
	}
	target := dest.String()
	req := o.request(http.MethodConnect, "", &url.URL{Host: target})
	req.Host = target
	if err := rs.SendRequestHeader(req); err != nil {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, err
	}
	if _, err := finish(rs); err != nil {
		return nil, err
	}
	return newStreamConn(rs, s.conn.LocalAddr(), s.conn.RemoteAddr()), nil
}

func (o *outbound) OpenPacket(ctx context.Context, dest addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("masque: udp is disabled")
	}
	f := newFlow(o.nat, o.openTarget)
	if _, err := f.lookup(ctx, dest); err != nil {
		f.Close()
		return nil, err
	}
	return f, nil
}

func (o *outbound) openTarget(ctx context.Context, dest addr.Addr) (*target, error) {
	rs, s, err := o.mgr.open(ctx)
	if err != nil {
		return nil, err
	}
	if !s.ext {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, errors.New("masque: server did not enable extended CONNECT")
	}
	u, err := url.Parse("https://" + o.authority + o.tpl.expand(dest))
	if err != nil {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, err
	}
	req := o.request(http.MethodConnect, "connect-udp", u)
	req.Header.Set("Capsule-Protocol", "?1")
	if err := rs.SendRequestHeader(req); err != nil {
		rs.CancelRead(codeConnect)
		rs.CancelWrite(codeConnect)
		return nil, err
	}
	if _, err := finish(rs); err != nil {
		return nil, err
	}
	return &target{peer: dest, st: rs, dg: s.dg && !o.noDG, recv: s.dg}, nil
}
