package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

const maxServerSessions = 8

type serverSession struct {
	aead cipher.AEAD
	win  window
	seen time.Time
}

type clientPacket struct {
	codec  datagramCodec
	sock   net.PacketConn
	server net.Addr
	chain  [][]byte
	sid    sessionID
	pid    atomic.Uint64
	out    outgoing
	xaead  cipher.AEAD

	mu      sync.Mutex
	remotes map[sessionID]*serverSession
	closed  atomic.Bool
}

func newClientPacket(s *suite, sock net.PacketConn, server net.Addr, chain [][]byte) *clientPacket {
	c := &clientPacket{
		codec:   datagramCodec{s},
		sock:    sock,
		server:  server,
		chain:   chain,
		remotes: map[sessionID]*serverSession{},
	}
	rand.Read(c.sid[:])
	user := chain[len(chain)-1]
	c.out = outgoing{sepKey: chain[0], layers: chain}
	if s.chacha {
		c.xaead, _ = chacha20poly1305.NewX(user)
		c.out.aead = c.xaead
	} else {
		c.out.aead = s.seal(derive(ctxSession, user, c.sid[:]))
	}
	return c
}

func (c *clientPacket) WritePacket(p []byte, peer addr.Addr) error {
	body, err := newBody(kindRequest, nil, peer, p)
	if err != nil {
		return err
	}
	pkt := c.codec.pack(&c.out, separate{c.sid, c.pid.Add(1) - 1}, body)
	_, err = c.sock.WriteTo(pkt, c.server)
	return err
}

func (c *clientPacket) remote(id sessionID, now time.Time) *serverSession {
	if r, ok := c.remotes[id]; ok {
		return r
	}
	if len(c.remotes) >= maxServerSessions {
		var oldest sessionID
		var at time.Time
		for k, r := range c.remotes {
			if at.IsZero() || r.seen.Before(at) {
				oldest, at = k, r.seen
			}
		}
		if now.Sub(at) < saltLife {
			return nil
		}
		delete(c.remotes, oldest)
	}
	r := &serverSession{}
	c.remotes[id] = r
	return r
}

func (c *clientPacket) ReadPacket(p []byte) (int, addr.Addr, error) {
	buf := bufpool.Get(maxChunk + 64)
	defer bufpool.Put(buf)
	for {
		n, from, err := c.sock.ReadFrom(buf)
		if err != nil {
			return 0, addr.Addr{}, err
		}
		if !sameEndpoint(from, c.server) {
			continue
		}
		peer, payload, ok := c.open(buf[:n])
		if !ok {
			continue
		}
		return copy(p, payload), peer, nil
	}
}

func (c *clientPacket) open(pkt []byte) (addr.Addr, []byte, bool) {
	s := c.codec.suite
	user := c.chain[len(c.chain)-1]
	var hdr separate
	var body []byte
	now := time.Now()
	if s.chacha {
		if len(pkt) < xnonce+16+tag {
			return addr.Addr{}, nil, false
		}
		plain, err := c.xaead.Open(nil, pkt[:xnonce], pkt[xnonce:], nil)
		if err != nil {
			return addr.Addr{}, nil, false
		}
		var raw [16]byte
		copy(raw[:], plain)
		hdr, body = splitSeparate(raw), plain[16:]
	} else {
		if len(pkt) < 16+tag {
			return addr.Addr{}, nil, false
		}
		raw := [16]byte(pkt[:16])
		ecbOpen(user, &raw)
		hdr = splitSeparate(raw)
		c.mu.Lock()
		known := c.remotes[hdr.session]
		c.mu.Unlock()
		var aead cipher.AEAD
		if known != nil {
			aead = known.aead
		} else {
			aead = s.seal(derive(ctxSession, user, hdr.session[:]))
		}
		plain, err := aead.Open(nil, raw[4:16], pkt[16:], nil)
		if err != nil {
			return addr.Addr{}, nil, false
		}
		body = plain
	}
	owner, peer, payload, err := openBody(kindResponse, true, body)
	if err != nil || owner != c.sid {
		return addr.Addr{}, nil, false
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	remote := c.remote(hdr.session, now)
	if remote == nil || !remote.win.fresh(hdr.packet) {
		return addr.Addr{}, nil, false
	}
	if remote.aead == nil && !s.chacha {
		remote.aead = s.seal(derive(ctxSession, user, hdr.session[:]))
	}
	remote.win.commit(hdr.packet)
	remote.seen = now
	return peer, payload, true
}

func (c *clientPacket) SetReadDeadline(t time.Time) error { return c.sock.SetReadDeadline(t) }

func (c *clientPacket) Close() error {
	if c.closed.Swap(true) {
		return nil
	}
	return c.sock.Close()
}

func sameEndpoint(a, b net.Addr) bool {
	x, ok1 := endpoint(a)
	y, ok2 := endpoint(b)
	return ok1 && ok2 && x == y
}

func endpoint(a net.Addr) (netip.AddrPort, bool) {
	switch v := a.(type) {
	case *net.UDPAddr:
		ip, ok := netip.AddrFromSlice(v.IP)
		return netip.AddrPortFrom(ip.Unmap(), uint16(v.Port)), ok
	}
	ap, err := netip.ParseAddrPort(a.String())
	return netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port()), err == nil
}
