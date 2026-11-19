package dialer

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"syscall"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
)

const (
	defaultTimeout = 10 * time.Second
	raceDelay      = 250 * time.Millisecond
)

type Options struct {
	BindInterface  string
	RoutingMark    uint32
	ConnectTimeout time.Duration
	Strategy       string
}

type StrategyResolver interface {
	LookupStrategy(ctx context.Context, host, strategy string) ([]netip.Addr, error)
}

type Dialer struct {
	opts     Options
	resolver adapter.Resolver
	detour   adapter.Outbound
}

func New(opts Options, res adapter.Resolver, detour adapter.Outbound) *Dialer {
	if opts.ConnectTimeout <= 0 {
		opts.ConnectTimeout = defaultTimeout
	}
	return &Dialer{opts: opts, resolver: res, detour: detour}
}

func (d *Dialer) control() func(network, address string, c syscall.RawConn) error {
	return controlFor(d.opts.BindInterface, d.opts.RoutingMark)
}

func (d *Dialer) lookup(ctx context.Context, host string) ([]netip.Addr, error) {
	if d.resolver == nil {
		return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	}
	if sr, ok := d.resolver.(StrategyResolver); ok && d.opts.Strategy != "" {
		return sr.LookupStrategy(ctx, host, d.opts.Strategy)
	}
	return d.resolver.Lookup(ctx, host)
}

func (d *Dialer) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, d.opts.ConnectTimeout)
	defer cancel()
	if d.detour != nil {
		return d.detour.DialStream(ctx, dest)
	}
	if dest.IsIP() {
		return d.dialOne(ctx, dest.AddrPort())
	}
	ips, err := d.lookup(ctx, dest.Host())
	if err != nil {
		return nil, fmt.Errorf("resolve %s: %w", dest.Host(), err)
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("resolve %s: no address", dest.Host())
	}
	return d.race(ctx, ips, dest.Port())
}

func (d *Dialer) dialOne(ctx context.Context, ap netip.AddrPort) (net.Conn, error) {
	nd := net.Dialer{
		Control:         d.control(),
		KeepAliveConfig: net.KeepAliveConfig{Enable: true, Idle: 30 * time.Second, Interval: 15 * time.Second, Count: 4},
	}
	return nd.DialContext(ctx, "tcp", ap.String())
}

func (d *Dialer) race(ctx context.Context, ips []netip.Addr, port uint16) (net.Conn, error) {
	ordered := interleave(ips)
	results := make(chan dialResult, len(ordered))
	raceCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	launch := func(ip netip.Addr) {
		go func() {
			c, err := d.dialOne(raceCtx, netip.AddrPortFrom(ip, port))
			results <- dialResult{c, err}
		}()
	}
	next, pending := 0, 0
	var errs []error
	timer := time.NewTimer(0)
	defer timer.Stop()
	for {
		select {
		case <-timer.C:
			if next < len(ordered) {
				launch(ordered[next])
				next++
				pending++
				timer.Reset(raceDelay)
			}
		case r := <-results:
			pending--
			if r.err == nil {
				cancel()
				go drain(results, pending)
				return r.conn, nil
			}
			errs = append(errs, r.err)
			if next < len(ordered) {
				launch(ordered[next])
				next++
				pending++
				timer.Reset(raceDelay)
			} else if pending == 0 {
				return nil, errors.Join(errs...)
			}
		case <-ctx.Done():
			go drain(results, pending)
			return nil, ctx.Err()
		}
	}
}

type dialResult struct {
	conn net.Conn
	err  error
}

func drain(results chan dialResult, n int) {
	for i := 0; i < n; i++ {
		if r := <-results; r.conn != nil {
			r.conn.Close()
		}
	}
}

func interleave(ips []netip.Addr) []netip.Addr {
	var v4, v6 []netip.Addr
	for _, ip := range ips {
		if ip.Is4() {
			v4 = append(v4, ip)
		} else {
			v6 = append(v6, ip)
		}
	}
	first, second := v4, v6
	if len(ips) > 0 && ips[0].Is6() {
		first, second = v6, v4
	}
	out := make([]netip.Addr, 0, len(ips))
	for i := 0; i < len(first) || i < len(second); i++ {
		if i < len(first) {
			out = append(out, first[i])
		}
		if i < len(second) {
			out = append(out, second[i])
		}
	}
	return out
}

func (d *Dialer) ListenPacket(ctx context.Context) (net.PacketConn, error) {
	if d.detour != nil {
		pc, err := d.detour.OpenPacket(ctx, addr.Addr{})
		if err != nil {
			return nil, err
		}
		return adapter.ToNet(pc), nil
	}
	lc := net.ListenConfig{Control: d.control()}
	return lc.ListenPacket(ctx, "udp", ":0")
}
