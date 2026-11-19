package anytls

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterOutbound("anytls", newOutbound)
}

type outboundOptions struct {
	Server                   string          `json:"server"`
	Password                 string          `json:"password"`
	TLS                      tlsx.Client     `json:"tls"`
	IdleSessionCheckInterval config.Duration `json:"idle_session_check_interval"`
	IdleSessionTimeout       config.Duration `json:"idle_session_timeout"`
	MinIdleSession           int             `json:"min_idle_session"`
	UDP                      *bool           `json:"udp"`
}

type outbound struct {
	env  *adapter.OutboundEnv
	pool *pool
	udp  bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("anytls: bad server %q (want host:port)", o.Server)
	}
	if o.Password == "" {
		return nil, errors.New("anytls: password is required")
	}
	if o.MinIdleSession < 0 {
		return nil, errors.New("anytls: min_idle_session must not be negative")
	}
	if _, err := o.TLS.Config(server.Host()); err != nil {
		return nil, fmt.Errorf("anytls: %w", err)
	}
	every, life := o.IdleSessionCheckInterval.Std(), o.IdleSessionTimeout.Std()
	if every <= 0 {
		every = 30 * time.Second
	}
	if life <= 0 {
		life = 30 * time.Second
	}
	dial := func(ctx context.Context) (net.Conn, error) {
		raw, err := env.Dialer.DialStream(ctx, server)
		if err != nil {
			return nil, err
		}
		cfg, err := o.TLS.Config(server.Host())
		if err != nil {
			raw.Close()
			return nil, err
		}
		tc := tls.Client(raw, cfg)
		if err := tc.HandshakeContext(ctx); err != nil {
			raw.Close()
			return nil, err
		}
		return tc, nil
	}
	return &outbound{
		env:  env,
		pool: newPool(dial, o.Password, every, life, o.MinIdleSession, env.Log),
		udp:  o.UDP == nil || *o.UDP,
	}, nil
}

func (o *outbound) Tag() string       { return o.env.Tag }
func (o *outbound) Type() string      { return "anytls" }
func (o *outbound) SupportsUDP() bool { return o.udp }
func (o *outbound) Close() error      { o.pool.close(); return nil }

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	return o.pool.dialStream(ctx, dest)
}

func (o *outbound) OpenPacket(ctx context.Context, dest addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("anytls: udp is disabled")
	}
	s, err := o.pool.dialStream(ctx, addr.FromDomain(uotHost, 0))
	if err != nil {
		return nil, err
	}
	req, err := uotRequest(false, dest)
	if err == nil {
		_, err = s.Write(req)
	}
	if err != nil {
		s.Close()
		return nil, err
	}
	return newUoTConn(s, bufio.NewReaderSize(s, 4096), false, addr.Addr{}), nil
}
