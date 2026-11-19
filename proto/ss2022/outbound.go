package ss2022

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
)

func init() {
	adapter.RegisterOutbound("ss2022", newOutbound)
}

type outboundOptions struct {
	Server   string `json:"server"`
	Method   string `json:"method"`
	Password string `json:"password"`
	UDP      *bool  `json:"udp"`
}

type outbound struct {
	env    *adapter.OutboundEnv
	suite  *suite
	server addr.Addr
	chain  [][]byte
	udp    bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("ss2022: %w", err)
	}
	s, err := suiteFor(o.Method)
	if err != nil {
		return nil, err
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("ss2022: bad server %q (want host:port)", o.Server)
	}
	if o.Password == "" {
		return nil, errors.New("ss2022: password is required")
	}
	if s.chacha && strings.Contains(o.Password, ":") {
		return nil, errors.New("ss2022: identity headers need an AES method")
	}
	var chain [][]byte
	for _, part := range strings.Split(o.Password, ":") {
		key, err := s.parseKey(part)
		if err != nil {
			return nil, err
		}
		chain = append(chain, key)
	}
	return &outbound{env: env, suite: s, server: server, chain: chain, udp: o.UDP == nil || *o.UDP}, nil
}

func (o *outbound) Tag() string       { return o.env.Tag }
func (o *outbound) Type() string      { return "ss2022" }
func (o *outbound) Close() error      { return nil }
func (o *outbound) SupportsUDP() bool { return o.udp }

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	conn, err := o.env.Dialer.DialStream(ctx, o.server)
	if err != nil {
		return nil, err
	}
	return dialTunnel(conn, o.suite, o.chain, dest), nil
}

func (o *outbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("ss2022: udp is disabled")
	}
	ip := o.server.IP()
	if o.server.IsDomain() {
		ips, err := o.env.Resolver.Lookup(ctx, o.server.Host())
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("ss2022: resolve %s: %v", o.server.Host(), err)
		}
		ip = ips[0]
	}
	sock, err := o.env.Dialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return newClientPacket(o.suite, sock, addr.FromIP(ip, o.server.Port()).UDPAddr(), o.chain), nil
}
