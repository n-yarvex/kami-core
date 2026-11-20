package wireguard

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
	"github.com/n-yarvex/kami-core/config"
)

func init() {
	adapter.RegisterOutbound("wireguard", newOutbound)
	adapter.RegisterInbound("wireguard", newInbound)
}

type outboundOptions struct {
	Server        string          `json:"server"`
	PrivateKey    string          `json:"private_key"`
	PeerPublicKey string          `json:"peer_public_key"`
	PresharedKey  string          `json:"preshared_key,omitempty"`
	LocalAddress  []string        `json:"local_address"`
	AllowedIPs    []string        `json:"allowed_ips,omitempty"`
	MTU           int             `json:"mtu,omitempty"`
	Reserved      []int           `json:"reserved,omitempty"`
	KeepAlive     config.Duration `json:"keepalive,omitempty"`
	DisableUDP    bool            `json:"disable_udp,omitempty"`
}

type outbound struct {
	env      *adapter.OutboundEnv
	server   addr.Addr
	cfg      string
	locals   []netip.Prefix
	mtu      int
	reserved *[3]byte
	udp      bool

	mu     sync.Mutex
	dev    *device.Device
	ts     *tunStack
	closed bool
}

func newOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o outboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("wireguard: bad server %q (want host:port)", o.Server)
	}
	priv, err := hexKey("private_key", o.PrivateKey)
	if err != nil {
		return nil, err
	}
	pub, err := hexKey("peer_public_key", o.PeerPublicKey)
	if err != nil {
		return nil, err
	}
	locals, err := parsePrefixes("local_address", o.LocalAddress)
	if err != nil {
		return nil, err
	}
	if len(locals) == 0 {
		return nil, errors.New("wireguard: local_address is required")
	}
	allowed := o.AllowedIPs
	if len(allowed) == 0 {
		allowed = []string{"0.0.0.0/0", "::/0"}
	}
	aps, err := parsePrefixes("allowed_ips", allowed)
	if err != nil {
		return nil, err
	}
	mtu, err := checkMTU(o.MTU)
	if err != nil {
		return nil, err
	}
	reserved, err := checkReserved(o.Reserved)
	if err != nil {
		return nil, err
	}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\npublic_key=%s\n", priv, pub)
	if o.PresharedKey != "" {
		psk, err := hexKey("preshared_key", o.PresharedKey)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "preshared_key=%s\n", psk)
	}
	if ka := o.KeepAlive.Std(); ka > 0 {
		fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", int(ka.Seconds()))
	}
	for _, p := range aps {
		fmt.Fprintf(&b, "allowed_ip=%s\n", p)
	}
	return &outbound{env: env, server: server, cfg: b.String(), locals: locals, mtu: mtu, reserved: reserved, udp: !o.DisableUDP}, nil
}

func (o *outbound) Tag() string       { return o.env.Tag }
func (o *outbound) Type() string      { return "wireguard" }
func (o *outbound) SupportsUDP() bool { return o.udp }

func (o *outbound) Close() error {
	o.mu.Lock()
	o.closed = true
	dev := o.dev
	o.dev, o.ts = nil, nil
	o.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	return nil
}

func (o *outbound) ensure(ctx context.Context) (*tunStack, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return nil, net.ErrClosed
	}
	if o.ts != nil {
		return o.ts, nil
	}
	target := o.server
	if target.IsDomain() {
		ips, err := o.env.Resolver.Lookup(ctx, target.Host())
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("wireguard: resolve %s: %v", target.Host(), err)
		}
		target = addr.FromIP(ips[0], target.Port())
	}
	ts, err := newTunStack(o.mtu, o.locals, false)
	if err != nil {
		return nil, err
	}
	mk := func() (net.PacketConn, error) {
		return o.env.Dialer.ListenPacket(context.Background())
	}
	dev := device.NewDevice(ts, newBind(mk, o.reserved), deviceLogger(o.env.Log, o.env.Tag))
	cfg := o.cfg + "endpoint=" + target.AddrPort().String() + "\n"
	if err := dev.IpcSet(cfg); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: configure: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("wireguard: up: %w", err)
	}
	o.dev, o.ts = dev, ts
	return ts, nil
}

func (o *outbound) localFor(ip netip.Addr) (netip.Addr, bool) {
	for _, p := range o.locals {
		if p.Addr().Is4() == ip.Is4() {
			return p.Addr(), true
		}
	}
	return netip.Addr{}, false
}

func (o *outbound) resolve(ctx context.Context, dest addr.Addr) (netip.Addr, error) {
	if dest.IsIP() {
		return dest.IP().Unmap(), nil
	}
	ips, err := o.env.Resolver.Lookup(ctx, dest.Host())
	if err != nil || len(ips) == 0 {
		return netip.Addr{}, fmt.Errorf("wireguard: resolve %s: %v", dest.Host(), err)
	}
	for _, ip := range ips {
		if _, ok := o.localFor(ip.Unmap()); ok {
			return ip.Unmap(), nil
		}
	}
	return ips[0].Unmap(), nil
}

func (o *outbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	ts, err := o.ensure(ctx)
	if err != nil {
		return nil, err
	}
	ip, err := o.resolve(ctx, dest)
	if err != nil {
		return nil, err
	}
	if _, ok := o.localFor(ip); !ok {
		return nil, errNoFamily
	}
	return gonet.DialContextTCP(ctx, ts.st, fullAddr(ip, dest.Port()), protoOf(ip))
}

func (o *outbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	if !o.udp {
		return nil, adapter.ErrNoUDP
	}
	ts, err := o.ensure(ctx)
	if err != nil {
		return nil, err
	}
	pc := &udpPC{o: o, in: make(chan udpIn, 256), done: make(chan struct{})}
	for _, p := range o.locals {
		local := p.Addr()
		if (local.Is4() && pc.v4 != nil) || (local.Is6() && pc.v6 != nil) {
			continue
		}
		fa := fullAddr(local, 0)
		c, err := gonet.DialUDP(ts.st, &fa, nil, protoOf(local))
		if err != nil {
			pc.Close()
			return nil, err
		}
		if local.Is4() {
			pc.v4 = c
		} else {
			pc.v6 = c
		}
		go pc.pump(c)
	}
	return pc, nil
}

type udpIn struct {
	data []byte
	from addr.Addr
}

type udpPC struct {
	o      *outbound
	v4, v6 *gonet.UDPConn
	in     chan udpIn
	done   chan struct{}
	once   sync.Once
	mu     sync.Mutex
	dl     time.Time
}

func (p *udpPC) pump(c *gonet.UDPConn) {
	buf := bufpool.Get(65535)
	defer bufpool.Put(buf)
	for {
		n, from, err := c.ReadFrom(buf)
		if err != nil {
			return
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok {
			continue
		}
		select {
		case p.in <- udpIn{data: append([]byte(nil), buf[:n]...), from: addr.FromNet(ua)}:
		case <-p.done:
			return
		default:
		}
	}
}

func (p *udpPC) ReadPacket(b []byte) (int, addr.Addr, error) {
	p.mu.Lock()
	dl := p.dl
	p.mu.Unlock()
	var timeout <-chan time.Time
	if !dl.IsZero() {
		d := time.Until(dl)
		if d <= 0 {
			return 0, addr.Addr{}, deadlineErr{}
		}
		t := time.NewTimer(d)
		defer t.Stop()
		timeout = t.C
	}
	select {
	case in := <-p.in:
		return copy(b, in.data), in.from, nil
	case <-p.done:
		return 0, addr.Addr{}, net.ErrClosed
	case <-timeout:
		return 0, addr.Addr{}, deadlineErr{}
	}
}

type deadlineErr struct{}

func (deadlineErr) Error() string   { return "i/o timeout" }
func (deadlineErr) Timeout() bool   { return true }
func (deadlineErr) Temporary() bool { return true }

func (p *udpPC) WritePacket(b []byte, peer addr.Addr) error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	ip, err := p.o.resolve(ctx, peer)
	if err != nil {
		return err
	}
	c := p.v6
	if ip.Is4() {
		c = p.v4
	}
	if c == nil {
		return errNoFamily
	}
	_, err = c.WriteTo(b, &net.UDPAddr{IP: ip.AsSlice(), Port: int(peer.Port())})
	return err
}

func (p *udpPC) SetReadDeadline(t time.Time) error {
	p.mu.Lock()
	p.dl = t
	p.mu.Unlock()
	return nil
}

func (p *udpPC) Close() error {
	p.once.Do(func() {
		close(p.done)
		if p.v4 != nil {
			p.v4.Close()
		}
		if p.v6 != nil {
			p.v6.Close()
		}
	})
	return nil
}
