package core

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/relay"
	"github.com/n-yarvex/kami-core/sniff"
)

const (
	sniffWait    = 300 * time.Millisecond
	firstWait    = 2 * time.Minute
	udpIdle      = 2 * time.Minute
	routeLookups = 3 * time.Second
)

type inboundPolicy struct {
	sniff        bool
	allowPrivate bool
}

type router struct {
	in *Instance
}

type replayConn struct {
	net.Conn
	head []byte
}

func (r *replayConn) Read(p []byte) (int, error) {
	if len(r.head) > 0 {
		n := copy(p, r.head)
		r.head = r.head[n:]
		return n, nil
	}
	return r.Conn.Read(p)
}

func (r *replayConn) CloseWrite() error {
	if cw, ok := r.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("half close unsupported")
}

func (r *router) pick(ctx context.Context, md adapter.Metadata) (adapter.Outbound, string) {
	in := r.in
	var tag string
	if in.engine.NeedsIP() {
		lctx, cancel := context.WithTimeout(ctx, routeLookups)
		defer cancel()
		tag = in.engine.Match(lctx, md, in.resolver.Lookup)
	} else {
		tag = in.engine.Match(ctx, md, nil)
	}
	ob, ok := in.outbounds[tag]
	if !ok {
		return nil, tag
	}
	return ob, tag
}

func (r *router) Stream(ctx context.Context, conn net.Conn, md adapter.Metadata) {
	in := r.in
	policy := in.policy[md.Inbound]
	if !policy.allowPrivate {
		ctx = adapter.WithDenyPrivate(ctx)
	}
	fail := func(err error) {
		if md.OnConnect != nil {
			md.OnConnect(err)
		}
		conn.Close()
	}
	if policy.sniff && md.Dest.IsIP() {
		if md.OnConnect != nil {
			md.OnConnect(nil)
			md.OnConnect = nil
		}
		head, res := sniff.Stream(conn, sniffWait)
		if len(head) > 0 {
			conn = &replayConn{Conn: conn, head: head}
		}
		md.Protocol = res.Protocol
		md.Domain = res.Domain
	}
	ob, tag := r.pick(ctx, md)
	if ob == nil {
		in.log.Warn("no outbound for connection", "inbound", md.Inbound, "outbound", tag, "dest", md.Target().String())
		fail(errors.New("no such outbound"))
		return
	}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	target := md.Dest
	if !target.IsIP() {
		target = md.Target()
	}
	remote, err := ob.DialStream(fctx, target)
	if md.OnConnect != nil {
		md.OnConnect(err)
	}
	if err != nil {
		in.log.Info("dial failed", "inbound", md.Inbound, "dest", md.Target().String(), "outbound", tag, "err", err)
		conn.Close()
		return
	}
	f := r.open(md, "tcp", tag, cancel)
	defer in.tracker.drop(f)
	in.log.Debug("tcp", "inbound", md.Inbound, "user", md.User, "dest", md.Target().String(), "outbound", tag)
	relay.Stream(fctx, conn, remote, r.meter(f))
}

func (r *router) open(md adapter.Metadata, network, tag string, cancel func()) *flow {
	f := &flow{
		Inbound: md.Inbound, User: md.User, Network: network,
		Source: md.Source.String(), Dest: md.Target().String(),
		Protocol: md.Protocol, Outbound: tag, Started: time.Now(), cancel: cancel,
	}
	r.in.tracker.add(f)
	return f
}

func (r *router) meter(f *flow) relay.Meter {
	t := r.in.tracker
	return relay.Meter{
		Up:   func(n int64) { f.addUp(n); t.up.Add(n) },
		Down: func(n int64) { f.addDown(n); t.down.Add(n) },
	}
}

type headPacket struct {
	adapter.PacketConn
	once sync.Once
	data []byte
	peer addr.Addr
}

func (h *headPacket) ReadPacket(p []byte) (int, addr.Addr, error) {
	var n int
	var peer addr.Addr
	var served bool
	h.once.Do(func() {
		n, peer, served = copy(p, h.data), h.peer, true
	})
	if served {
		return n, peer, nil
	}
	return h.PacketConn.ReadPacket(p)
}

func (r *router) Packet(ctx context.Context, pc adapter.PacketConn, md adapter.Metadata) {
	in := r.in
	defer pc.Close()
	policy := in.policy[md.Inbound]
	if !policy.allowPrivate {
		ctx = adapter.WithDenyPrivate(ctx)
	}
	buf := make([]byte, 65535)
	pc.SetReadDeadline(time.Now().Add(firstWait))
	n, dest, err := pc.ReadPacket(buf)
	if err != nil {
		return
	}
	pc.SetReadDeadline(time.Time{})
	md.Dest = dest
	md.Network = "udp"
	ob, tag := r.pick(ctx, md)
	if ob == nil {
		in.log.Warn("no outbound for datagram session", "inbound", md.Inbound, "outbound", tag)
		return
	}
	if nc, ok := ob.(adapter.NetworkChecker); ok && !nc.SupportsUDP() {
		in.log.Info("outbound has no udp support, session dropped", "outbound", tag)
		return
	}
	fctx, cancel := context.WithCancel(ctx)
	defer cancel()
	remote, err := ob.OpenPacket(fctx, dest)
	if err != nil {
		in.log.Info("udp open failed", "inbound", md.Inbound, "dest", dest.String(), "outbound", tag, "err", err)
		return
	}
	first := &headPacket{PacketConn: pc, data: append([]byte(nil), buf[:n]...), peer: dest}
	f := r.open(md, "udp", tag, cancel)
	defer in.tracker.drop(f)
	in.log.Debug("udp", "inbound", md.Inbound, "user", md.User, "dest", dest.String(), "outbound", tag)
	relay.Packets(fctx, first, remote, udpIdle, r.meter(f))
}
