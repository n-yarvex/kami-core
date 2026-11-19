package noise

import (
	"math"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/net/ipv4"
)

type Role uint8

const (
	Client Role = iota
	Server
)

const (
	peerIdle   = 10 * time.Minute
	queueLimit = 64
	sweepEvery = time.Minute
)

type Stats struct {
	Trains     uint64
	Packets    uint64
	Bytes      uint64
	Suppressed uint64
	Overflow   uint64
	QueueDrops uint64
}

type Statser interface {
	NoiseStats() Stats
}

type queued struct {
	b, oob []byte
	dst    net.Addr
}

type peer struct {
	mu      sync.Mutex
	pending atomic.Bool
	due     atomic.Int64
	rx      atomic.Int64
	seen    atomic.Int64
	spent   int64
	queue   []queued
}

type core struct {
	plan    *Plan
	role    Role
	raw     func(b, oob []byte, dst net.Addr) error
	peers   sync.Map
	count   atomic.Int64
	swept   atomic.Int64
	counter atomic.Uint32
	done    chan struct{}
	once    sync.Once

	trains, packets, bytes, suppressed, overflow, drops atomic.Uint64
}

func newCore(p *Plan, role Role, raw func(b, oob []byte, dst net.Addr) error) *core {
	return &core{plan: p, role: role, raw: raw, done: make(chan struct{})}
}

func (c *core) stop() { c.once.Do(func() { close(c.done) }) }

func (c *core) stats() Stats {
	return Stats{c.trains.Load(), c.packets.Load(), c.bytes.Load(), c.suppressed.Load(), c.overflow.Load(), c.drops.Load()}
}

func key(a netip.AddrPort) netip.AddrPort { return netip.AddrPortFrom(a.Addr().Unmap(), a.Port()) }

func (c *core) lookup(a netip.AddrPort, create bool) *peer {
	if v, ok := c.peers.Load(a); ok {
		return v.(*peer)
	}
	if !create {
		return nil
	}
	now := time.Now().UnixNano()
	if c.count.Load() >= int64(c.plan.maxPeers) || now-c.swept.Load() > int64(sweepEvery) {
		c.sweep(now)
	}
	if c.count.Load() >= int64(c.plan.maxPeers) {
		c.overflow.Add(1)
		return nil
	}
	v, loaded := c.peers.LoadOrStore(a, &peer{})
	if !loaded {
		c.count.Add(1)
		v.(*peer).seen.Store(now)
	}
	return v.(*peer)
}

func (c *core) sweep(now int64) {
	last := c.swept.Load()
	if now-last < int64(time.Second) && c.swept.Load() != 0 {
		return
	}
	if !c.swept.CompareAndSwap(last, now) {
		return
	}
	c.peers.Range(func(k, v any) bool {
		p := v.(*peer)
		if !p.pending.Load() && now-p.seen.Load() > int64(peerIdle) {
			if _, ok := c.peers.LoadAndDelete(k); ok {
				c.count.Add(-1)
			}
		}
		return true
	})
}

func (c *core) received(a netip.AddrPort, n int) {
	if c.role != Server {
		return
	}
	if p := c.lookup(key(a), true); p != nil {
		p.rx.Add(int64(n))
		p.seen.Store(time.Now().UnixNano())
	}
}

func (c *core) nextDue(now int64) int64 {
	if c.plan.resetMax <= 0 {
		return math.MaxInt64
	}
	d := c.plan.resetMin
	if c.plan.resetMax > d {
		d += time.Duration(span(0, int(c.plan.resetMax-c.plan.resetMin)/int(time.Millisecond))) * time.Millisecond
	}
	return now + int64(d)
}

func (c *core) write(a netip.AddrPort, dst net.Addr, b, oob []byte) error {
	select {
	case <-c.done:
		return net.ErrClosed
	default:
	}
	p := c.lookup(key(a), c.role == Client)
	if p == nil {
		return c.raw(b, oob, dst)
	}
	now := time.Now().UnixNano()
	p.seen.Store(now)
	if !p.pending.Load() && p.due.Load() > now {
		return c.raw(b, oob, dst)
	}
	p.mu.Lock()
	if p.pending.Load() {
		c.enqueue(p, b, oob, dst)
		p.mu.Unlock()
		return nil
	}
	if p.due.Load() > now {
		p.mu.Unlock()
		return c.raw(b, oob, dst)
	}
	if c.plan.async {
		p.pending.Store(true)
		c.enqueue(p, b, oob, dst)
		p.mu.Unlock()
		go c.runTrain(p, dst)
		return nil
	}
	c.sendTrain(p, dst, false)
	p.due.Store(c.nextDue(now))
	err := c.raw(b, oob, dst)
	p.mu.Unlock()
	return err
}

func (c *core) enqueue(p *peer, b, oob []byte, dst net.Addr) {
	if len(p.queue) >= queueLimit {
		c.drops.Add(1)
		return
	}
	q := queued{b: append([]byte(nil), b...), dst: cloneAddr(dst)}
	if len(oob) > 0 {
		q.oob = append([]byte(nil), oob...)
	}
	p.queue = append(p.queue, q)
}

func cloneAddr(a net.Addr) net.Addr {
	if u, ok := a.(*net.UDPAddr); ok {
		cp := *u
		cp.IP = append(net.IP(nil), u.IP...)
		return &cp
	}
	return a
}

func (c *core) sendTrain(p *peer, dst net.Addr, pause bool) bool {
	c.trains.Add(1)
	var buf []byte
	for i := range c.plan.items {
		it := &c.plan.items[i]
		buf = it.build(buf, &c.counter)
		if len(buf) > 0 {
			if c.role == Server && float64(p.spent+int64(len(buf))) > float64(p.rx.Load())*c.plan.ampCap {
				c.suppressed.Add(1)
				return true
			}
			if c.raw(buf, nil, dst) == nil {
				p.spent += int64(len(buf))
				c.packets.Add(1)
				c.bytes.Add(uint64(len(buf)))
			}
		}
		if pause {
			if d := it.delay(); d > 0 {
				t := time.NewTimer(d)
				select {
				case <-t.C:
				case <-c.done:
					t.Stop()
					return false
				}
			}
		}
	}
	return true
}

func (c *core) runTrain(p *peer, dst net.Addr) {
	ok := c.sendTrain(p, dst, true)
	p.mu.Lock()
	defer p.mu.Unlock()
	if !ok {
		p.queue = nil
		p.pending.Store(false)
		return
	}
	p.due.Store(c.nextDue(time.Now().UnixNano()))
	for _, q := range p.queue {
		c.raw(q.b, q.oob, q.dst)
	}
	p.queue = nil
	p.pending.Store(false)
}

func addrPort(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		return v.AddrPort(), true
	case interface{ AddrPort() netip.AddrPort }:
		return v.AddrPort(), true
	}
	ap, err := netip.ParseAddrPort(a.String())
	return ap, err == nil
}

type basicConn struct {
	net.PacketConn
	c *core
}

func (b *basicConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := b.PacketConn.ReadFrom(p)
	if err == nil && b.c.role == Server {
		if ap, ok := addrPort(a); ok {
			b.c.received(ap, n)
		}
	}
	return n, a, err
}

func (b *basicConn) WriteTo(p []byte, a net.Addr) (int, error) {
	ap, ok := addrPort(a)
	if !ok {
		return b.PacketConn.WriteTo(p, a)
	}
	if err := b.c.write(ap, a, p, nil); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (b *basicConn) Close() error {
	b.c.stop()
	return b.PacketConn.Close()
}

func (b *basicConn) NoiseStats() Stats { return b.c.stats() }

type udpConn struct {
	*net.UDPConn
	c  *core
	bc *ipv4.PacketConn
}

func (u *udpConn) ReadBatch(ms []ipv4.Message, flags int) (int, error) {
	n, err := u.bc.ReadBatch(ms, flags)
	if err == nil && u.c.role == Server {
		for i := 0; i < n; i++ {
			if ua, ok := ms[i].Addr.(*net.UDPAddr); ok {
				u.c.received(ua.AddrPort(), ms[i].N)
			}
		}
	}
	return n, err
}

func (u *udpConn) ReadFrom(p []byte) (int, net.Addr, error) {
	n, a, err := u.UDPConn.ReadFrom(p)
	if err == nil && u.c.role == Server {
		if ap, ok := addrPort(a); ok {
			u.c.received(ap, n)
		}
	}
	return n, a, err
}

func (u *udpConn) ReadMsgUDP(b, oob []byte) (int, int, int, *net.UDPAddr, error) {
	n, oobn, flags, a, err := u.UDPConn.ReadMsgUDP(b, oob)
	if err == nil && u.c.role == Server && a != nil {
		u.c.received(a.AddrPort(), n)
	}
	return n, oobn, flags, a, err
}

func (u *udpConn) WriteTo(p []byte, a net.Addr) (int, error) {
	ap, ok := addrPort(a)
	if !ok {
		return u.UDPConn.WriteTo(p, a)
	}
	if err := u.c.write(ap, a, p, nil); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (u *udpConn) WriteMsgUDP(b, oob []byte, a *net.UDPAddr) (int, int, error) {
	if err := u.c.write(a.AddrPort(), a, b, oob); err != nil {
		return 0, 0, err
	}
	return len(b), len(oob), nil
}

func (u *udpConn) Close() error {
	u.c.stop()
	return u.UDPConn.Close()
}

func (u *udpConn) NoiseStats() Stats { return u.c.stats() }

func Wrap(pc net.PacketConn, p *Plan, role Role) net.PacketConn {
	if uc, ok := pc.(*net.UDPConn); ok {
		w := &udpConn{UDPConn: uc, bc: ipv4.NewPacketConn(uc)}
		w.c = newCore(p, role, func(b, oob []byte, dst net.Addr) error {
			ua, ok := dst.(*net.UDPAddr)
			if !ok {
				_, err := uc.WriteTo(b, dst)
				return err
			}
			_, _, err := uc.WriteMsgUDP(b, oob, ua)
			return err
		})
		return w
	}
	w := &basicConn{PacketConn: pc}
	w.c = newCore(p, role, func(b, _ []byte, dst net.Addr) error {
		_, err := pc.WriteTo(b, dst)
		return err
	})
	return w
}
