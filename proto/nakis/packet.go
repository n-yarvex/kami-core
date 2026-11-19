package nakis

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

type packetItem struct {
	data []byte
	from addr.Addr
}

type packetLink struct {
	recv   chan packetItem
	done   chan struct{}
	once   sync.Once
	rd     *deadline
	mux    *jitterMux
	last   atomic.Int64
	napped atomic.Bool
	mc     *Tunnel
	failed atomic.Pointer[error]
}

func newPacketLink(mc *Tunnel) *packetLink {
	p := &packetLink{
		recv: make(chan packetItem, udpRecvCap),
		done: make(chan struct{}),
		rd:   newDeadline(),
		mc:   mc,
	}
	p.last.Store(time.Now().UnixNano())
	return p
}

func (p *packetLink) deliver(from addr.Addr, data []byte) {
	cp := bufpool.Get(len(data))
	copy(cp, data)
	select {
	case p.recv <- packetItem{data: cp, from: from}:
	default:
		bufpool.Put(cp)
	}
}

func (p *packetLink) ReadPacket(b []byte) (int, addr.Addr, error) {
	select {
	case <-p.done:
		return 0, addr.Addr{}, p.closeError()
	case <-p.rd.wait():
		return 0, addr.Addr{}, os.ErrDeadlineExceeded
	default:
	}
	select {
	case item, ok := <-p.recv:
		if !ok {
			return 0, addr.Addr{}, p.closeError()
		}
		n := copy(b, item.data)
		bufpool.Put(item.data)
		return n, item.from, nil
	case <-p.done:
		return 0, addr.Addr{}, p.closeError()
	case <-p.rd.wait():
		return 0, addr.Addr{}, os.ErrDeadlineExceeded
	}
}

func (p *packetLink) closeError() error {
	if err := p.failed.Load(); err != nil {
		return *err
	}
	select {
	case <-p.done:
		return net.ErrClosed
	default:
		return io.EOF
	}
}

func (p *packetLink) WritePacket(b []byte, peer addr.Addr) error {
	select {
	case <-p.done:
		return net.ErrClosed
	default:
	}
	if peer.Port() == 0 {
		return errors.New("nakis: missing destination port")
	}
	if p.mux.failed.Load() {
		return io.ErrClosedPipe
	}
	buf := bufpool.Get(peer.SocksLen() + 2 + len(b))
	rec, err := appendRecord(buf[:0], peer, b)
	if err != nil {
		bufpool.Put(buf)
		return err
	}
	p.last.Store(time.Now().UnixNano())
	p.mux.push(rec)
	return nil
}

func (p *packetLink) SetReadDeadline(t time.Time) error {
	p.rd.set(t)
	return nil
}

func (p *packetLink) drainRecv() {
	for {
		select {
		case item, ok := <-p.recv:
			if !ok {
				return
			}
			bufpool.Put(item.data)
		default:
			return
		}
	}
}

func (p *packetLink) watchIdle(ctx context.Context, idle time.Duration, quit <-chan struct{}, idled *atomic.Bool) {
	ticker := time.NewTicker(udpTick)
	defer ticker.Stop()
	for {
		select {
		case <-quit:
			return
		case <-ctx.Done():
			_ = p.mc.Close()
			return
		case <-ticker.C:
			if time.Since(time.Unix(0, p.last.Load())) > idle {
				idled.Store(true)
				_ = p.mc.Close()
				return
			}
		}
	}
}

var (
	_ adapter.PacketConn = (*servicePacket)(nil)
	_ adapter.PacketConn = (*clientPacket)(nil)
)

type servicePacket struct {
	*packetLink
	srv   *Service
	ended sync.Once
	endOK bool
}

func (s *Service) servePackets(ctx context.Context, mc *Tunnel, who origin) bool {
	if s.opts.DisableUDP {
		_ = mc.Send(nil, ErrorBytes(0, "udp is switched off on this server"))
		return false
	}
	if sendWithPad(mc, OKByte) != nil {
		return false
	}
	br := bufio.NewReaderSize(mc, 16<<10)
	buffer := make([]byte, 0xFFFF)
	_ = mc.SetReadDeadline(time.Now().Add(s.opts.UDPIdleTimeout))
	first, data, err := readRecord(br, buffer)
	if err != nil {
		if errors.Is(err, ErrNap) {
			return mc.Nap() == nil
		}
		return false
	}
	_ = mc.SetReadDeadline(time.Time{})

	pc := &servicePacket{packetLink: newPacketLink(mc), srv: s}
	pc.mux = newJitterMux(s.opts.UDPJitter, func(b []byte) error { return mc.Send(nil, b) })
	pc.deliver(first, data)
	s.log.Debug("udp association", "from", who.source.String(), "first", first.String())
	md := adapter.Metadata{
		Inbound:     s.opts.Tag,
		InboundType: "nakis",
		User:        who.user,
		Network:     "udp",
		Source:      who.source,
		Dest:        first,
	}
	if !s.route(func() {
		s.opts.Router.Packet(ctx, pc, md)
		_ = pc.Close()
	}) {
		_ = pc.Close()
		return false
	}
	return pc.consume(ctx, br, buffer)
}

func (p *servicePacket) consume(ctx context.Context, br *bufio.Reader, buffer []byte) bool {
	quit := make(chan struct{})
	var idled atomic.Bool
	go p.watchIdle(ctx, p.srv.opts.UDPIdleTimeout, quit, &idled)

	var err error
	for {
		var a addr.Addr
		var data []byte
		a, data, err = readRecord(br, buffer)
		if err != nil {
			break
		}
		p.last.Store(time.Now().UnixNano())
		p.deliver(a, data)
	}
	close(quit)
	close(p.recv)
	p.once.Do(func() { close(p.done) })
	if idled.Load() {
		p.srv.log.Debug("udp association idle for too long, closed")
		p.end(false)
		return false
	}
	if !errors.Is(err, ErrNap) {
		p.end(false)
		return false
	}
	return p.end(true)
}

func (p *servicePacket) end(nap bool) bool {
	p.ended.Do(func() {
		p.mux.close()
		p.endOK = nap && !p.mux.failed.Load() && p.mc.Nap() == nil
		if p.endOK {
			_ = p.mc.SetReadDeadline(time.Now().Add(p.srv.opts.HalfCloseTimeout))
		}
	})
	return p.endOK
}

func (p *servicePacket) Close() error {
	first := false
	p.once.Do(func() {
		first = true
		close(p.done)
	})
	if first {
		go p.end(true)
	}
	return nil
}

type clientPacket struct {
	*packetLink
	client *Client
	ref    *sessionRef
	lease  *leased
	ended  sync.Once
}

func (c *Client) OpenPacket(ctx context.Context) (adapter.PacketConn, error) {
	ref, ok := c.beginSession(nil)
	if !ok {
		return nil, net.ErrClosed
	}
	l, err := c.dialTunnel(ctx, uotHost, 0)
	if err != nil {
		c.endSession(ref)
		return nil, err
	}
	if !ref.bind(l.mc) {
		_ = l.mc.Close()
		c.endSession(ref)
		return nil, net.ErrClosed
	}
	if err = sendWithPad(l.mc, l.first); err != nil {
		l.broken.Store(true)
		l.release()
		c.endSession(ref)
		return nil, err
	}
	pc := &clientPacket{
		packetLink: newPacketLink(l.mc),
		client:     c,
		ref:        ref,
		lease:      l,
	}
	ref.access.Lock()
	ref.closer = func() { _ = pc.Close() }
	ref.access.Unlock()
	pc.mux = newJitterMux(c.opts.UDPJitter, func(b []byte) error {
		err := l.mc.Send(nil, b)
		if err != nil {
			l.broken.Store(true)
		}
		return err
	})
	go pc.run()
	return pc, nil
}

func (p *clientPacket) run() {
	defer func() {
		if r := recover(); r != nil {
			p.client.log.Error("recovered from a crash while serving a udp association", "panic", r)
		}
	}()
	p.down()
	p.once.Do(func() { close(p.done) })
	p.end()
	p.drainRecv()
	p.lease.release()
	p.client.endSession(p.ref)
}

func (p *clientPacket) down() {
	l := p.lease
	mc := l.mc
	if err := mc.ReadReply(); err != nil {
		l.broken.Store(true)
		var mew *PeerError
		if errors.As(err, &mew) {
			p.client.log.Warn("the server refused to carry udp", "err", err)
		} else {
			p.client.hintOnce(err)
		}
		p.fail(fmt.Errorf("nakis: udp tunnel: %w", err))
		return
	}
	br := bufio.NewReaderSize(mc, 16<<10)
	buffer := make([]byte, 0xFFFF)
	for {
		a, data, err := readRecord(br, buffer)
		if err != nil {
			if errors.Is(err, ErrNap) {
				l.napSeen.Store(true)
			} else {
				l.broken.Store(true)
				p.fail(fmt.Errorf("nakis: udp tunnel: %w", err))
			}
			return
		}
		p.last.Store(time.Now().UnixNano())
		p.deliver(a, data)
	}
}

func (p *clientPacket) fail(err error) {
	p.failed.CompareAndSwap(nil, &err)
	p.once.Do(func() { close(p.done) })
}

func (p *clientPacket) end() {
	p.ended.Do(func() {
		l := p.lease
		p.mux.close()
		if p.mux.failed.Load() {
			l.broken.Store(true)
		}
		if !l.broken.Load() && l.napSent.CompareAndSwap(false, true) {
			if err := l.mc.Nap(); err != nil {
				l.broken.Store(true)
			}
		}
		_ = l.mc.SetReadDeadline(time.Now().Add(p.client.drainWindow()))
	})
}

func (p *clientPacket) Close() error {
	first := false
	p.once.Do(func() {
		first = true
		close(p.done)
	})
	if first {
		go p.end()
	}
	return nil
}
