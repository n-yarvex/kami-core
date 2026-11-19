package ss2022

import (
	"context"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

const (
	maxClientSessions = 4096
	sessionQueue      = 128
)

type inDatagram struct {
	buf  []byte
	n    int
	dest addr.Addr
	off  int
}

type clientSession struct {
	srv   *packetServer
	id    sessionID
	user  string
	key   []byte
	aead  cipher.AEAD
	reply outgoing
	ssid  sessionID
	spid  atomic.Uint64

	mu     sync.Mutex
	win    window
	remote net.Addr
	last   time.Time
	queue  chan inDatagram
	done   chan struct{}
	once   sync.Once
	dline  atomic.Pointer[time.Time]
}

type packetServer struct {
	acc     *acceptor
	sock    net.PacketConn
	env     *adapter.InboundEnv
	codec   datagramCodec
	timeout time.Duration

	mu       sync.Mutex
	sessions map[sessionID]*clientSession
	wg       sync.WaitGroup
	stop     chan struct{}
}

func newPacketServer(a *acceptor, sock net.PacketConn, env *adapter.InboundEnv, timeout time.Duration) *packetServer {
	return &packetServer{
		acc:      a,
		sock:     sock,
		env:      env,
		codec:    datagramCodec{a.suite},
		timeout:  timeout,
		sessions: map[sessionID]*clientSession{},
		stop:     make(chan struct{}),
	}
}

func (p *packetServer) run() {
	p.wg.Add(2)
	go func() {
		defer p.wg.Done()
		p.sweep()
	}()
	go func() {
		defer p.wg.Done()
		buf := make([]byte, maxChunk+64)
		for {
			n, from, err := p.sock.ReadFrom(buf)
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				continue
			}
			p.receive(buf[:n], from)
		}
	}()
}

func (p *packetServer) sweep() {
	tick := time.NewTicker(p.timeout / 4)
	defer tick.Stop()
	for {
		select {
		case <-p.stop:
			return
		case now := <-tick.C:
			var idle []*clientSession
			p.mu.Lock()
			for _, s := range p.sessions {
				s.mu.Lock()
				if now.Sub(s.last) > p.timeout {
					idle = append(idle, s)
				}
				s.mu.Unlock()
			}
			p.mu.Unlock()
			for _, s := range idle {
				s.Close()
			}
		}
	}
}

func (p *packetServer) shut() {
	close(p.stop)
	p.sock.Close()
	p.mu.Lock()
	live := make([]*clientSession, 0, len(p.sessions))
	for _, s := range p.sessions {
		live = append(live, s)
	}
	p.mu.Unlock()
	for _, s := range live {
		s.Close()
	}
	p.wg.Wait()
}

func (p *packetServer) lookup(id sessionID) *clientSession {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.sessions[id]
}

func (p *packetServer) receive(pkt []byte, from net.Addr) {
	s := p.acc.suite
	var hdr separate
	var body []byte
	var user *account
	var existing *clientSession
	if s.chacha {
		if len(pkt) < xnonce+16+tag {
			return
		}
		aead, _ := chacha20poly1305.NewX(p.acc.key)
		plain, err := aead.Open(nil, pkt[:xnonce], pkt[xnonce:], nil)
		if err != nil {
			return
		}
		var raw [16]byte
		copy(raw[:], plain)
		hdr, body = splitSeparate(raw), plain[16:]
		user = &account{key: p.acc.key}
		existing = p.lookup(hdr.session)
	} else {
		floor := 16 + tag
		if p.acc.users != nil {
			floor += 16
		}
		if len(pkt) < floor {
			return
		}
		raw := [16]byte(pkt[:16])
		ecbOpen(p.acc.key, &raw)
		hdr = splitSeparate(raw)
		user = &account{key: p.acc.key}
		start := 16
		if p.acc.users != nil {
			blk := [16]byte(pkt[16:32])
			ecbOpen(p.acc.key, &blk)
			for i := range blk {
				blk[i] ^= raw[i]
			}
			who, ok := p.acc.users[blk]
			if !ok {
				return
			}
			user = who
			start = 32
		}
		existing = p.lookup(hdr.session)
		var aead cipher.AEAD
		if existing != nil {
			if existing.user != user.name {
				return
			}
			aead = existing.aead
		} else {
			aead = s.seal(derive(ctxSession, user.key, hdr.session[:]))
		}
		plain, err := aead.Open(nil, raw[4:16], pkt[start:], nil)
		if err != nil {
			return
		}
		body = plain
	}
	_, dest, payload, err := openBody(kindRequest, false, body)
	if err != nil {
		return
	}
	sess := existing
	if sess == nil {
		if sess = p.create(hdr.session, user, from); sess == nil {
			return
		}
	}
	sess.mu.Lock()
	if !sess.win.fresh(hdr.packet) {
		sess.mu.Unlock()
		return
	}
	sess.win.commit(hdr.packet)
	sess.remote = from
	sess.last = time.Now()
	sess.mu.Unlock()

	buf := bufpool.Get(len(payload))
	copy(buf, payload)
	select {
	case sess.queue <- inDatagram{buf: buf, n: len(payload), dest: dest}:
	default:
		bufpool.Put(buf)
	}
}

func (p *packetServer) create(id sessionID, user *account, from net.Addr) *clientSession {
	p.mu.Lock()
	if old, ok := p.sessions[id]; ok {
		p.mu.Unlock()
		if old.user != user.name {
			return nil
		}
		return old
	}
	if len(p.sessions) >= maxClientSessions {
		p.mu.Unlock()
		return nil
	}
	s := &clientSession{
		srv:    p,
		id:     id,
		user:   user.name,
		key:    user.key,
		last:   time.Now(),
		remote: from,
		queue:  make(chan inDatagram, sessionQueue),
		done:   make(chan struct{}),
	}
	rand.Read(s.ssid[:])
	if p.acc.suite.chacha {
		x, _ := chacha20poly1305.NewX(user.key)
		s.aead = x
	} else {
		s.aead = p.acc.suite.seal(derive(ctxSession, user.key, id[:]))
	}
	s.reply = outgoing{sepKey: user.key, layers: [][]byte{user.key}}
	if p.acc.suite.chacha {
		s.reply.aead = s.aead
	} else {
		s.reply.aead = p.acc.suite.seal(derive(ctxSession, user.key, s.ssid[:]))
	}
	p.sessions[id] = s
	p.mu.Unlock()

	md := adapter.Metadata{
		Source:      addr.FromNet(from),
		Inbound:     p.env.Tag,
		InboundType: "ss2022",
		User:        user.name,
		Network:     "udp",
	}
	p.wg.Add(1)
	go func() {
		defer p.wg.Done()
		p.env.Router.Packet(p.env.Ctx, s, md)
		s.Close()
	}()
	return s
}

func (s *clientSession) ReadPacket(b []byte) (int, addr.Addr, error) {
	var timeout <-chan time.Time
	if d := s.dline.Load(); d != nil && !d.IsZero() {
		wait := time.NewTimer(time.Until(*d))
		defer wait.Stop()
		timeout = wait.C
	}
	select {
	case d := <-s.queue:
		n := copy(b, d.buf[:d.n])
		bufpool.Put(d.buf)
		return n, d.dest, nil
	case <-s.done:
		return 0, addr.Addr{}, net.ErrClosed
	case <-timeout:
		return 0, addr.Addr{}, context.DeadlineExceeded
	}
}

func (s *clientSession) WritePacket(b []byte, peer addr.Addr) error {
	select {
	case <-s.done:
		return net.ErrClosed
	default:
	}
	body, err := newBody(kindResponse, &s.id, peer, b)
	if err != nil {
		return err
	}
	pkt := s.srv.codec.pack(&s.reply, separate{s.ssid, s.spid.Add(1) - 1}, body)
	s.mu.Lock()
	to := s.remote
	s.last = time.Now()
	s.mu.Unlock()
	_, err = s.srv.sock.WriteTo(pkt, to)
	return err
}

func (s *clientSession) SetReadDeadline(t time.Time) error {
	s.dline.Store(&t)
	return nil
}

func (s *clientSession) Close() error {
	s.once.Do(func() {
		close(s.done)
		s.srv.mu.Lock()
		delete(s.srv.sessions, s.id)
		s.srv.mu.Unlock()
	})
	return nil
}
