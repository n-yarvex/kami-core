package masque

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterInbound("masque", newInbound)
}

type userOption struct {
	Name     string `json:"name"`
	Password string `json:"password"`
	Token    string `json:"token"`
}

type inboundOptions struct {
	transportOptions
	Users      []userOption    `json:"users"`
	TLS        tlsx.Server     `json:"tls"`
	Path       string          `json:"path"`
	Fallback   coverOptions    `json:"fallback"`
	Challenge  bool            `json:"challenge"`
	MaxStreams int             `json:"max_streams"`
	UDPTimeout config.Duration `json:"udp_timeout"`
	DisableUDP bool            `json:"disable_udp"`
}

type inbound struct {
	env       *adapter.InboundEnv
	tls       *tls.Config
	qcfg      *quic.Config
	tpl       *template
	accts     *accounts
	cover     *cover
	challenge bool
	nat       time.Duration
	udp       bool
	idle      time.Duration

	mu     sync.Mutex
	srv    *http3.Server
	pc     net.PacketConn
	closed bool
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("masque: %w", err)
	}
	if len(o.Users) == 0 {
		return nil, errors.New("masque: users is required (an open proxy is not allowed)")
	}
	accts := &accounts{}
	seen := map[string]bool{}
	for i, u := range o.Users {
		if u.Name == "" {
			u.Name = fmt.Sprintf("user%d", i+1)
		}
		if seen[u.Name] {
			return nil, fmt.Errorf("masque: duplicate user %q", u.Name)
		}
		seen[u.Name] = true
		switch {
		case u.Token != "" && u.Password != "":
			return nil, fmt.Errorf("masque: user %q has both password and token", u.Name)
		case u.Token != "":
			accts.add(u.Name, bearerValue(u.Token))
		case u.Password != "":
			accts.add(u.Name, basicValue(u.Name, u.Password))
		default:
			return nil, fmt.Errorf("masque: user %q needs a password or a token", u.Name)
		}
	}
	tpl, err := compileTemplate(o.Path)
	if err != nil {
		return nil, err
	}
	cv, err := newCover(o.Fallback)
	if err != nil {
		return nil, err
	}
	streams := o.MaxStreams
	if streams == 0 {
		streams = 1024
	}
	if streams < 8 {
		return nil, errors.New("masque: max_streams must be at least 8")
	}
	qcfg, err := o.quicConfig(int64(streams))
	if err != nil {
		return nil, err
	}
	tcfg, err := o.TLS.Config()
	if err != nil {
		return nil, fmt.Errorf("masque: %w", err)
	}
	in := &inbound{
		env: env, tls: forceH3(tcfg), qcfg: qcfg, tpl: tpl, accts: accts, cover: cv,
		challenge: o.Challenge, nat: o.UDPTimeout.Std(), udp: !o.DisableUDP, idle: qcfg.MaxIdleTimeout,
	}
	if in.nat <= 0 {
		in.nat = flowNAT + time.Minute
	}
	return in, nil
}

func (in *inbound) Tag() string  { return in.env.Tag }
func (in *inbound) Type() string { return "masque" }

func (in *inbound) Start() error {
	pc, err := in.env.ListenUDP()
	if err != nil {
		return err
	}
	srv := &http3.Server{
		Handler:         in,
		TLSConfig:       in.tls,
		QUICConfig:      in.qcfg,
		EnableDatagrams: true,
	}
	in.mu.Lock()
	in.srv, in.pc = srv, pc
	in.mu.Unlock()
	in.wg.Add(1)
	go func() {
		defer in.wg.Done()
		srv.Serve(pc)
	}()
	return nil
}

func (in *inbound) Close() error {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return nil
	}
	in.closed = true
	srv, pc := in.srv, in.pc
	in.mu.Unlock()
	if srv != nil {
		srv.Close()
	}
	if pc != nil {
		pc.Close()
	}
	in.wg.Wait()
	return nil
}

func (in *inbound) refuse(w http.ResponseWriter) {
	if in.challenge {
		w.Header().Set("Proxy-Authenticate", `Basic realm="proxy"`)
		w.WriteHeader(http.StatusProxyAuthRequired)
		return
	}
	in.cover.serve(w)
}

func (in *inbound) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		in.cover.serve(w)
		return
	}
	user, ok := in.accts.check(r.Header.Get("Proxy-Authorization"))
	if !ok {
		in.refuse(w)
		return
	}
	md := adapter.Metadata{
		Inbound:     in.env.Tag,
		InboundType: "masque",
		User:        user,
		Source:      remoteOf(r),
	}
	switch r.Proto {
	case "", "HTTP/3.0", "HTTP/3":
		in.serveTCP(w, r, md)
	case "connect-udp":
		in.serveUDP(w, r, md)
	default:
		in.cover.serve(w)
	}
}

func remoteOf(r *http.Request) addr.Addr {
	a, err := addr.Parse(r.RemoteAddr)
	if err != nil {
		return addr.Addr{}
	}
	return a
}

func (in *inbound) serveTCP(w http.ResponseWriter, r *http.Request, md adapter.Metadata) {
	dest, err := parseAuthority(r.Host)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	md.Network, md.Dest = "tcp", dest
	local := in.localAddr()
	conn := newStreamConn(nil, local, remoteNet(r))
	md.OnConnect = func(err error) {
		if err != nil {
			w.WriteHeader(statusFor(err))
			conn.abandon()
			return
		}
		w.WriteHeader(http.StatusOK)
		conn.bind(w.(http3.HTTPStreamer).HTTPStream())
	}
	in.env.Router.Stream(r.Context(), conn, md)
}

func (in *inbound) serveUDP(w http.ResponseWriter, r *http.Request, md adapter.Metadata) {
	if !in.udp {
		in.cover.serve(w)
		return
	}
	dest, err := in.tpl.match(r.URL.RequestURI())
	if err != nil {
		in.cover.serve(w)
		return
	}
	w.Header().Set("Capsule-Protocol", "?1")
	w.WriteHeader(http.StatusOK)
	st := w.(http3.HTTPStreamer).HTTPStream()
	t := &target{peer: dest, st: st, dg: true, recv: true}
	f := newFlow(in.nat, nil)
	f.only = t
	f.adopt(t)
	md.Network, md.Dest = "udp", dest
	in.env.Router.Packet(r.Context(), f, md)
	f.Close()
}

func (in *inbound) localAddr() net.Addr {
	in.mu.Lock()
	defer in.mu.Unlock()
	if in.pc != nil {
		return in.pc.LocalAddr()
	}
	return &net.UDPAddr{}
}

func remoteNet(r *http.Request) net.Addr {
	if ap, err := netipParse(r.RemoteAddr); err == nil {
		return net.UDPAddrFromAddrPort(ap)
	}
	return &net.UDPAddr{}
}

func statusFor(err error) int {
	var ne net.Error
	if errors.Is(err, context.DeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		return http.StatusGatewayTimeout
	}
	return http.StatusBadGateway
}
