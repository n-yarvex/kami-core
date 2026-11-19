package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/route"
)

var ErrForbidden = errors.New("destination is not allowed")

func init() {
	adapter.RegisterOutbound("direct", func(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
		var o struct{}
		if err := adapter.Decode(raw, &o); err != nil {
			return nil, fmt.Errorf("direct: %w", err)
		}
		return &direct{env: env}, nil
	})
	adapter.RegisterOutbound("block", func(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
		var o struct{}
		if err := adapter.Decode(raw, &o); err != nil {
			return nil, fmt.Errorf("block: %w", err)
		}
		return &block{tag: env.Tag}, nil
	})
}

type direct struct {
	env *adapter.OutboundEnv
}

func (d *direct) Tag() string  { return d.env.Tag }
func (d *direct) Type() string { return "direct" }
func (d *direct) Close() error { return nil }

func (d *direct) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	if !adapter.DenyPrivate(ctx) {
		return d.env.Dialer.DialStream(ctx, dest)
	}
	ips, err := d.allowed(ctx, dest)
	if err != nil {
		return nil, err
	}
	var last error
	for _, ip := range ips {
		c, err := d.env.Dialer.DialStream(ctx, addr.FromIP(ip, dest.Port()))
		if err == nil {
			return c, nil
		}
		last = err
	}
	return nil, last
}

func (d *direct) allowed(ctx context.Context, dest addr.Addr) ([]netip.Addr, error) {
	if dest.IsIP() {
		if route.IsInternal(dest.IP()) {
			return nil, ErrForbidden
		}
		return []netip.Addr{dest.IP()}, nil
	}
	ips, err := d.env.Resolver.Lookup(ctx, dest.Host())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", dest.Host(), err)
	}
	var ok []netip.Addr
	for _, ip := range ips {
		if !route.IsInternal(ip) {
			ok = append(ok, ip)
		}
	}
	if len(ok) == 0 {
		return nil, ErrForbidden
	}
	return ok, nil
}

func (d *direct) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	pc, err := d.env.Dialer.ListenPacket(ctx)
	if err != nil {
		return nil, err
	}
	return &directPacket{pc: pc, d: d, deny: adapter.DenyPrivate(ctx)}, nil
}

type directPacket struct {
	pc   net.PacketConn
	d    *direct
	deny bool
	mu   sync.Mutex
	pins map[string]netip.Addr
}

func (p *directPacket) ReadPacket(b []byte) (int, addr.Addr, error) {
	n, from, err := p.pc.ReadFrom(b)
	if err != nil {
		return 0, addr.Addr{}, err
	}
	return n, addr.FromNet(from), nil
}

func (p *directPacket) WritePacket(b []byte, peer addr.Addr) error {
	ip := peer.IP()
	if peer.IsDomain() {
		var err error
		if ip, err = p.resolve(peer.Host()); err != nil {
			return err
		}
	}
	if p.deny && route.IsInternal(ip) {
		return ErrForbidden
	}
	_, err := p.pc.WriteTo(b, net.UDPAddrFromAddrPort(netip.AddrPortFrom(ip, peer.Port())))
	return err
}

func (p *directPacket) resolve(host string) (netip.Addr, error) {
	p.mu.Lock()
	ip, ok := p.pins[host]
	p.mu.Unlock()
	if ok {
		return ip, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ips, err := p.d.env.Resolver.Lookup(ctx, host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, c := range ips {
		if p.deny && route.IsInternal(c) {
			continue
		}
		p.mu.Lock()
		if p.pins == nil {
			p.pins = map[string]netip.Addr{}
		}
		if len(p.pins) < 64 {
			p.pins[host] = c
		}
		p.mu.Unlock()
		return c, nil
	}
	return netip.Addr{}, ErrForbidden
}

func (p *directPacket) SetReadDeadline(t time.Time) error { return p.pc.SetReadDeadline(t) }
func (p *directPacket) Close() error                      { return p.pc.Close() }

type block struct{ tag string }

func (b *block) Tag() string  { return b.tag }
func (b *block) Type() string { return "block" }
func (b *block) Close() error { return nil }

func (b *block) DialStream(context.Context, addr.Addr) (net.Conn, error) {
	return nil, errors.New("blocked by rule")
}

func (b *block) OpenPacket(context.Context, addr.Addr) (adapter.PacketConn, error) {
	return nil, errors.New("blocked by rule")
}
