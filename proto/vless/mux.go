package vless

import (
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
)

type inPacket struct {
	data []byte
	peer addr.Addr
}

type detachPC struct {
	in     chan inPacket
	done   chan struct{}
	once   sync.Once
	dl     *deadline
	onDone func()

	mu    sync.Mutex
	out   func(frame) error
	id    uint16
	owner uint64
	timer *time.Timer
}

func newDetachPC(onDone func()) *detachPC {
	return &detachPC{
		in:     make(chan inPacket, 512),
		done:   make(chan struct{}),
		dl:     newDeadline(),
		onDone: onDone,
	}
}

func (d *detachPC) attach(owner uint64, id uint16, out func(frame) error) {
	d.mu.Lock()
	d.out, d.id, d.owner = out, id, owner
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	d.mu.Unlock()
}

func (d *detachPC) detach(owner uint64, hold time.Duration) {
	d.mu.Lock()
	if d.owner != owner {
		d.mu.Unlock()
		return
	}
	d.out = nil
	if hold > 0 {
		if d.timer != nil {
			d.timer.Stop()
		}
		d.timer = time.AfterFunc(hold, func() { d.Close() })
		d.mu.Unlock()
		return
	}
	d.mu.Unlock()
	d.Close()
}

func (d *detachPC) push(data []byte, peer addr.Addr) {
	select {
	case d.in <- inPacket{data: data, peer: peer}:
	default:
	}
}

func (d *detachPC) ReadPacket(p []byte) (int, addr.Addr, error) {
	select {
	case <-d.done:
		return 0, addr.Addr{}, errClosed
	default:
	}
	select {
	case pk := <-d.in:
		return copy(p, pk.data), pk.peer, nil
	case <-d.done:
		return 0, addr.Addr{}, errClosed
	case <-d.dl.wait():
		return 0, addr.Addr{}, timeoutError{}
	}
}

func (d *detachPC) WritePacket(p []byte, peer addr.Addr) error {
	select {
	case <-d.done:
		return errClosed
	default:
	}
	d.mu.Lock()
	out, id := d.out, d.id
	d.mu.Unlock()
	if out == nil {
		return nil
	}
	return out(frame{id: id, status: stKeep, option: optData, dest: peer, data: p})
}

func (d *detachPC) SetReadDeadline(t time.Time) error {
	d.dl.set(t)
	return nil
}

func (d *detachPC) Close() error {
	d.once.Do(func() {
		close(d.done)
		d.mu.Lock()
		if d.timer != nil {
			d.timer.Stop()
		}
		d.mu.Unlock()
		if d.onDone != nil {
			d.onDone()
		}
	})
	return nil
}

type timeoutError struct{}

func (timeoutError) Error() string   { return "i/o timeout" }
func (timeoutError) Timeout() bool   { return true }
func (timeoutError) Temporary() bool { return true }

type globalKey struct {
	user UUID
	g    [8]byte
}

type registry struct {
	mu sync.Mutex
	m  map[globalKey]*detachPC
}

func newRegistry() *registry { return &registry{m: map[globalKey]*detachPC{}} }

type muxServer struct {
	env   *adapter.InboundEnv
	typ   string
	reg   *registry
	hold  time.Duration
	owner uint64
	mu    sync.Mutex
}

func (m *muxServer) nextOwner() uint64 {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.owner++
	return m.owner
}

type serverSession struct {
	pc     *detachPC
	dest   addr.Addr
	global bool
	key    globalKey
}

func (m *muxServer) run(l link, userName string, user UUID, src addr.Addr) {
	owner := m.nextOwner()
	sessions := map[uint16]*serverSession{}
	defer func() {
		for _, s := range sessions {
			if s.global {
				s.pc.detach(owner, m.hold)
			} else {
				s.pc.Close()
			}
		}
	}()
	for {
		f, err := l.recv()
		if err != nil {
			return
		}
		switch f.status {
		case stKeepAlive:
			if _, ok := l.(*dgramLink); ok {
				l.send(frame{status: stKeepAlive})
			}
		case stNew:
			if old := sessions[f.id]; old != nil {
				if old.global {
					old.pc.detach(owner, m.hold)
				} else {
					old.pc.Close()
				}
				delete(sessions, f.id)
			}
			if f.network != netUDP {
				l.send(frame{id: f.id, status: stEnd, option: optError})
				continue
			}
			s := m.open(l, owner, userName, user, src, f)
			sessions[f.id] = s
			if f.hasData() {
				s.pc.push(f.data, f.dest)
			}
		case stKeep:
			s := sessions[f.id]
			if s == nil {
				l.send(frame{id: f.id, status: stEnd, option: optError})
				continue
			}
			if !f.hasData() {
				continue
			}
			peer := f.dest
			if !peer.IsValid() {
				peer = s.dest
			}
			s.pc.push(f.data, peer)
		case stEnd:
			if s := sessions[f.id]; s != nil {
				s.pc.Close()
				delete(sessions, f.id)
			}
		}
	}
}

func (m *muxServer) open(l link, owner uint64, userName string, user UUID, src addr.Addr, f frame) *serverSession {
	out := func(r frame) error { return l.send(r) }
	s := &serverSession{dest: f.dest}
	if f.global != [8]byte{} {
		s.global = true
		s.key = globalKey{user: user, g: f.global}
		m.reg.mu.Lock()
		if pc := m.reg.m[s.key]; pc != nil {
			select {
			case <-pc.done:
			default:
				m.reg.mu.Unlock()
				pc.attach(owner, f.id, out)
				s.pc = pc
				return s
			}
		}
		pc := newDetachPC(func() {
			m.reg.mu.Lock()
			if m.reg.m[s.key] != nil && m.reg.m[s.key] == s.pc {
				delete(m.reg.m, s.key)
			}
			m.reg.mu.Unlock()
		})
		s.pc = pc
		m.reg.m[s.key] = pc
		m.reg.mu.Unlock()
	} else {
		s.pc = newDetachPC(nil)
	}
	s.pc.attach(owner, f.id, out)
	pc := s.pc
	md := adapter.Metadata{
		Inbound:     m.env.Tag,
		InboundType: m.typ,
		User:        userName,
		Network:     "udp",
		Source:      src,
		Dest:        f.dest,
	}
	go func() {
		m.env.Router.Packet(m.env.Ctx, pc, md)
		pc.Close()
	}()
	return s
}
