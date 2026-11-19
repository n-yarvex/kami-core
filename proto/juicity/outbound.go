package juicity

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/proto/juicity/noise"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterOutbound("juicity", newOutbound)
}

type outboundOptions struct {
	transportOptions
	Server     string          `json:"server"`
	UUID       string          `json:"uuid"`
	Password   string          `json:"password"`
	TLS        tlsx.Client     `json:"tls"`
	UDPTimeout config.Duration `json:"udp_timeout"`
	DisableUDP bool            `json:"disable_udp"`
}

type outbound struct {
	env *adapter.OutboundEnv
	mgr *manager
	nat time.Duration
	udp bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("juicity: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("juicity: bad server %q (want host:port)", o.Server)
	}
	id, err := parseUUID(o.UUID)
	if err != nil {
		return nil, err
	}
	if o.Password == "" {
		return nil, errors.New("juicity: password is required")
	}
	tcfg, err := o.TLS.Config(server.Host())
	if err != nil {
		return nil, fmt.Errorf("juicity: %w", err)
	}
	tcfg = forceH3(tcfg)
	qcfg, err := o.quicConfig(16)
	if err != nil {
		return nil, err
	}
	plan, err := o.plan()
	if err != nil {
		return nil, err
	}
	cred := credential{id: id, password: o.Password}
	ob := &outbound{env: env, nat: o.UDPTimeout.Std(), udp: !o.DisableUDP}
	if ob.nat <= 0 {
		ob.nat = clientNAT
	}
	if plan != nil {
		env.Log.Info("juicity noise enabled", "outbound", env.Tag, "plan", plan.Describe())
	}
	ob.mgr = &manager{establish: func(ctx context.Context) (*session, error) {
		return dialSession(ctx, env, server, tcfg, qcfg, plan, cred)
	}}
	return ob, nil
}

func resolveServer(ctx context.Context, env *adapter.OutboundEnv, server addr.Addr) (*net.UDPAddr, error) {
	if server.IsIP() {
		return server.UDPAddr(), nil
	}
	ips, err := env.Resolver.Lookup(ctx, server.Host())
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("juicity: no address for %s", server.Host())
	}
	pick := ips[0]
	for _, ip := range ips {
		if ip.Is4() {
			pick = ip
			break
		}
	}
	return net.UDPAddrFromAddrPort(netip.AddrPortFrom(pick, server.Port())), nil
}

func dialSession(ctx context.Context, env *adapter.OutboundEnv, server addr.Addr, tcfg *tls.Config, qcfg *quic.Config, plan *noise.Plan, cred credential) (*session, error) {
	remote, err := resolveServer(ctx, env, server)
	if err != nil {
		return nil, err
	}
	pc, err := env.Dialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	var wire net.PacketConn = pc
	if plan != nil {
		wire = noise.Wrap(pc, plan, noise.Client)
	}
	tr := &quic.Transport{Conn: wire}
	conn, err := tr.Dial(ctx, remote, tcfg, qcfg)
	if err != nil {
		tr.Close()
		wire.Close()
		return nil, err
	}
	s := &session{conn: conn, tr: tr, pc: wire}
	cs := conn.ConnectionState().TLS
	frame, err := authFrame(&cs, cred)
	if err == nil {
		var us *quic.SendStream
		if us, err = conn.OpenUniStream(); err == nil {
			if _, err = us.Write(frame); err == nil {
				err = us.Close()
			}
		}
	}
	if err != nil {
		s.shutdown(1)
		return nil, err
	}
	go func() {
		<-conn.Context().Done()
		tr.Close()
		wire.Close()
	}()
	return s, nil
}

func (o *outbound) Tag() string       { return o.env.Tag }
func (o *outbound) Type() string      { return "juicity" }
func (o *outbound) SupportsUDP() bool { return o.udp }
func (o *outbound) Close() error      { o.mgr.shutdown(); return nil }

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	st, c, err := o.mgr.open(ctx)
	if err != nil {
		return nil, err
	}
	head, err := appendHeader(nil, netTCP, dest)
	if err != nil {
		st.CancelRead(0)
		st.Close()
		return nil, err
	}
	tc := newTCPConn(st, nil, c.LocalAddr(), c.RemoteAddr())
	tc.holdHeader(head, headerWait)
	return tc, nil
}

func (o *outbound) OpenPacket(ctx context.Context, dest addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("juicity: udp is disabled")
	}
	st, _, err := o.mgr.open(ctx)
	if err != nil {
		return nil, err
	}
	return newDatagramConn(st, bufio.NewReaderSize(st, 4096), true, o.nat), nil
}
