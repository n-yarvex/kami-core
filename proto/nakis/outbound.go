package nakis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterOutbound("nakis", newOutbound)
}

type outboundOptions struct {
	Server           string          `json:"server"`
	UUID             string          `json:"uuid"`
	TLS              tlsx.Client     `json:"tls"`
	HandshakeTimeout config.Duration `json:"handshake_timeout"`
	RaceCount        int             `json:"race_count"`
	PoolLo           int             `json:"pool_lo"`
	PoolHi           int             `json:"pool_hi"`
	PoolMaxAge       config.Duration `json:"pool_max_age"`
	PoolMaxUses      int             `json:"pool_max_uses"`
	SendPack         int             `json:"send_pack"`
	SendTail         int             `json:"send_tail"`
	SendQuiet        int             `json:"send_quiet"`
	ShapeUp          []string        `json:"shape_up"`
	ShapeWait        config.Duration `json:"shape_wait"`
	HalfCloseTimeout config.Duration `json:"half_close_timeout"`
	UDPJitter        config.Duration `json:"udp_jitter"`
	DisableUDP       bool            `json:"disable_udp"`
}

type outbound struct {
	env    *adapter.OutboundEnv
	client *Client
	cancel context.CancelFunc
	udp    bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("nakis: %w", err)
	}
	var servers []addr.Addr
	for _, s := range strings.Split(o.Server, ",") {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		a, err := addr.Parse(s)
		if err != nil || a.Port() == 0 {
			return nil, fmt.Errorf("nakis: bad server %q (want host:port)", s)
		}
		servers = append(servers, a)
	}
	if len(servers) == 0 {
		return nil, errors.New("nakis: server is required")
	}
	if len(o.TLS.ALPN) == 0 {
		o.TLS.ALPN = []string{"h2", "http/1.1"}
	}
	for _, s := range servers {
		if _, err := o.TLS.Config(s.Host()); err != nil {
			return nil, fmt.Errorf("nakis: %w", err)
		}
	}
	ranges, err := parseRanges(o.ShapeUp)
	if err != nil {
		return nil, fmt.Errorf("nakis: %w", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	c, err := NewClient(ClientOptions{
		Context: ctx,
		Log:     env.Log,
		UUID:    o.UUID,
		Servers: servers,
		DialOut: func(ctx context.Context, server addr.Addr) (net.Conn, error) {
			return env.Dialer.DialStream(ctx, server)
		},
		Handshake: func(ctx context.Context, server addr.Addr, conn net.Conn) (net.Conn, error) {
			cfg, err := o.TLS.Config(server.Host())
			if err != nil {
				return nil, err
			}
			tc := tls.Client(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
		HandshakeTimeout: o.HandshakeTimeout.Std(),
		RaceCount:        o.RaceCount,
		PoolLo:           o.PoolLo,
		PoolHi:           o.PoolHi,
		PoolMaxAge:       o.PoolMaxAge.Std(),
		PoolMaxUses:      o.PoolMaxUses,
		SendPack:         o.SendPack,
		SendTail:         o.SendTail,
		SendQuiet:        o.SendQuiet,
		ShapeUp:          ranges,
		ShapeWait:        o.ShapeWait.Std(),
		HalfCloseTimeout: o.HalfCloseTimeout.Std(),
		UDPJitter:        o.UDPJitter.Std(),
	})
	if err != nil {
		cancel()
		return nil, err
	}
	return &outbound{env: env, client: c, cancel: cancel, udp: !o.DisableUDP}, nil
}

func (o *outbound) Tag() string  { return o.env.Tag }
func (o *outbound) Type() string { return "nakis" }

func (o *outbound) Start() error {
	o.client.Start()
	return nil
}

func (o *outbound) SupportsUDP() bool { return o.udp }

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	return o.client.DialStream(ctx, dest)
}

func (o *outbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, errors.New("nakis: udp is disabled")
	}
	return o.client.OpenPacket(ctx)
}

func (o *outbound) Close() error {
	err := o.client.Close()
	o.cancel()
	return err
}
