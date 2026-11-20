package vless

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	"github.com/pion/turn/v4"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

type TURN struct {
	Server    string          `json:"server"`
	Transport string          `json:"transport,omitempty"`
	Username  string          `json:"username"`
	Password  string          `json:"password"`
	Realm     string          `json:"realm,omitempty"`
	Software  string          `json:"software,omitempty"`
	RTO       config.Duration `json:"rto,omitempty"`
	TLS       *tlsx.UClient   `json:"tls,omitempty"`
}

func (t *TURN) Validate() error {
	server, err := addr.Parse(t.Server)
	if err != nil || server.Port() == 0 {
		return fmt.Errorf("turn: bad server %q (want host:port)", t.Server)
	}
	switch strings.ToLower(t.Transport) {
	case "", "udp", "tcp":
		if t.TLS != nil {
			return errors.New("turn: tls only applies to transport tls")
		}
	case "tls":
		if t.TLS == nil {
			t.TLS = &tlsx.UClient{}
		}
		if err := t.TLS.Validate(server.Host()); err != nil {
			return fmt.Errorf("turn: %w", err)
		}
	default:
		return fmt.Errorf("turn: unknown transport %q (udp, tcp, tls)", t.Transport)
	}
	if t.Username == "" || t.Password == "" {
		return errors.New("turn: username and password are required")
	}
	return nil
}

func (t *TURN) allocate(ctx context.Context, env *adapter.OutboundEnv) (net.PacketConn, *turn.Client, error) {
	server, err := addr.Parse(t.Server)
	if err != nil {
		return nil, nil, err
	}
	target := server
	if server.IsDomain() {
		ips, err := env.Resolver.Lookup(ctx, server.Host())
		if err != nil || len(ips) == 0 {
			return nil, nil, fmt.Errorf("turn: resolve %s: %v", server.Host(), err)
		}
		target = addr.FromIP(ips[0], server.Port())
	}
	var base net.PacketConn
	switch strings.ToLower(t.Transport) {
	case "", "udp":
		if base, err = env.Dialer.ListenPacket(ctx); err != nil {
			return nil, nil, err
		}
	case "tcp", "tls":
		conn, err := env.Dialer.DialStream(ctx, target)
		if err != nil {
			return nil, nil, err
		}
		if strings.ToLower(t.Transport) == "tls" {
			tc, err := t.TLS.Handshake(ctx, conn, server.Host(), nil)
			if err != nil {
				conn.Close()
				return nil, nil, err
			}
			conn = tc
		}
		base = turn.NewSTUNConn(conn)
	}
	cfg := &turn.ClientConfig{
		STUNServerAddr: target.String(),
		TURNServerAddr: target.String(),
		Username:       t.Username,
		Password:       t.Password,
		Realm:          t.Realm,
		Software:       t.Software,
		RTO:            t.RTO.Std(),
		Conn:           base,
	}
	cl, err := turn.NewClient(cfg)
	if err != nil {
		base.Close()
		return nil, nil, err
	}
	if err := cl.Listen(); err != nil {
		cl.Close()
		base.Close()
		return nil, nil, err
	}
	type result struct {
		pc  net.PacketConn
		err error
	}
	ch := make(chan result, 1)
	go func() {
		pc, err := cl.Allocate()
		ch <- result{pc, err}
	}()
	select {
	case r := <-ch:
		if r.err != nil {
			cl.Close()
			base.Close()
			return nil, nil, fmt.Errorf("turn allocate: %w", r.err)
		}
		return &turnRelay{PacketConn: r.pc, base: base}, cl, nil
	case <-ctx.Done():
		cl.Close()
		base.Close()
		go func() {
			if r := <-ch; r.pc != nil {
				r.pc.Close()
			}
		}()
		return nil, nil, ctx.Err()
	}
}

type turnRelay struct {
	net.PacketConn
	base net.PacketConn
}

func (t *turnRelay) Close() error {
	err := t.PacketConn.Close()
	t.base.Close()
	return err
}
