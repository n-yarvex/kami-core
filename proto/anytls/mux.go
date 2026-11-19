package anytls

import (
	"io"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n-yarvex/kami-core/bufpool"
)

const (
	writeStall   = 60 * time.Duration(1e9)
	synAckBudget = 3 * time.Second
)

type muxHooks struct {
	accept   func(s *stream)
	scheme   func(raw string)
	settings func(peer map[string]string)
	alert    func(text string)
}

type mux struct {
	conn   net.Conn
	client bool
	hooks  muxHooks
	shape  *scheme

	wmu     sync.Mutex
	sent    int
	shaping bool
	holding bool
	held    []byte

	mu      sync.Mutex
	streams map[uint32]*stream
	next    uint32
	peerVer atomic.Int32
	gotCfg  bool

	dead     chan struct{}
	dieOnce  sync.Once
	dieHook  func()
	watchdog *time.Timer

	seq       uint64
	idleSince time.Time
	touched   atomic.Int64
}

func newMux(conn net.Conn, client bool, shape *scheme, h muxHooks) *mux {
	m := &mux{
		conn:    conn,
		client:  client,
		hooks:   h,
		shape:   shape,
		shaping: true,
		streams: map[uint32]*stream{},
		dead:    make(chan struct{}),
	}
	m.peerVer.Store(1)
	m.touched.Store(time.Now().UnixNano())
	return m
}

func (m *mux) alive() bool { return !isClosed(m.dead) }

func (m *mux) kill() {
	m.dieOnce.Do(func() {
		close(m.dead)
		m.conn.Close()
		m.mu.Lock()
		all := make([]*stream, 0, len(m.streams))
		for _, s := range m.streams {
			all = append(all, s)
		}
		m.streams = map[uint32]*stream{}
		if m.watchdog != nil {
			m.watchdog.Stop()
		}
		hook := m.dieHook
		m.mu.Unlock()
		for _, s := range all {
			s.shut(errSessionDead, false)
		}
		if hook != nil {
			hook()
		}
	})
}

func (m *mux) put(frame []byte) error {
	m.wmu.Lock()
	defer m.wmu.Unlock()
	if m.holding {
		m.held = append(m.held, frame...)
		return nil
	}
	if len(m.held) > 0 {
		frame = append(m.held, frame...)
		m.held = nil
	}
	m.conn.SetWriteDeadline(time.Now().Add(writeStall))
	if err := m.shaped(frame); err != nil {
		go m.kill()
		return err
	}
	return nil
}

func (m *mux) shaped(b []byte) error {
	if m.shaping {
		m.sent++
		if m.sent >= m.shape.stop {
			m.shaping = false
		} else {
			for _, size := range m.shape.plan(m.sent) {
				if size == checkMark {
					if len(b) == 0 {
						break
					}
					continue
				}
				switch {
				case len(b) > size:
					if _, err := m.conn.Write(b[:size]); err != nil {
						return err
					}
					b = b[size:]
				case len(b) > 0:
					if gap := size - len(b); gap >= headLen {
						b = append(b[:len(b):len(b)], wasteFrame(gap)...)
					}
					if _, err := m.conn.Write(b); err != nil {
						return err
					}
					b = nil
				default:
					if _, err := m.conn.Write(wasteFrame(size)); err != nil {
						return err
					}
				}
			}
			if len(b) == 0 {
				return nil
			}
		}
	}
	_, err := m.conn.Write(b)
	return err
}

func (m *mux) push(sid uint32, data []byte) error {
	if !m.alive() {
		return errSessionDead
	}
	buf := bufpool.Get(headLen + len(data))
	frame := appendFrame(buf[:0], opPush, sid, data)
	err := m.put(frame)
	bufpool.Put(buf)
	return err
}

func (m *mux) control(op byte, sid uint32, body []byte) error {
	if !m.alive() {
		return errSessionDead
	}
	return m.put(appendFrame(nil, op, sid, body))
}

func (m *mux) fin(sid uint32) {
	m.mu.Lock()
	delete(m.streams, sid)
	m.mu.Unlock()
	if m.alive() {
		m.control(opFin, sid, nil)
	}
}

func (m *mux) open() (*stream, error) {
	m.mu.Lock()
	if !m.alive() {
		m.mu.Unlock()
		return nil, errSessionDead
	}
	m.next++
	sid := m.next
	s := newStream(sid, m)
	m.streams[sid] = s
	arm := sid >= 2 && m.peerVer.Load() >= 2
	if arm {
		if m.watchdog != nil {
			m.watchdog.Stop()
		}
		m.watchdog = time.AfterFunc(synAckBudget, m.kill)
	}
	m.mu.Unlock()
	if err := m.control(opSyn, sid, nil); err != nil {
		return nil, err
	}
	m.wmu.Lock()
	m.holding = false
	m.wmu.Unlock()
	return s, nil
}

func (m *mux) hello() error {
	m.wmu.Lock()
	m.holding = true
	m.wmu.Unlock()
	return m.control(opSettings, 0, encodeKV("v", strconv.Itoa(protoVersion), "client", clientName, "padding-md5", m.shape.sum))
}

func (m *mux) quiet(limit time.Duration) bool {
	m.mu.Lock()
	n := len(m.streams)
	m.mu.Unlock()
	return n == 0 && time.Since(time.Unix(0, m.touched.Load())) > limit
}

func (m *mux) lookup(sid uint32) *stream {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.streams[sid]
}

func (m *mux) serve() {
	defer m.kill()
	var head [headLen]byte
	for {
		if _, err := io.ReadFull(m.conn, head[:]); err != nil {
			return
		}
		op := head[0]
		sid := uint32(head[1])<<24 | uint32(head[2])<<16 | uint32(head[3])<<8 | uint32(head[4])
		n := int(head[5])<<8 | int(head[6])
		var body []byte
		if n > 0 {
			body = bufpool.Get(n)[:n]
			if _, err := io.ReadFull(m.conn, body); err != nil {
				bufpool.Put(body)
				return
			}
		}
		ok := m.dispatch(op, sid, body)
		if body != nil {
			bufpool.Put(body)
		}
		if !ok {
			return
		}
	}
}

func (m *mux) dispatch(op byte, sid uint32, body []byte) bool {
	switch op {
	case opSyn, opPush, opFin:
		m.touched.Store(time.Now().UnixNano())
	}
	switch op {
	case opPush:
		if s := m.lookup(sid); s != nil && len(body) > 0 {
			if !s.in.push(body, m.dead) && !m.alive() {
				return false
			}
		}
	case opSyn:
		if m.client {
			return true
		}
		if !m.gotCfg {
			m.control(opAlert, 0, []byte("client did not send its settings"))
			return false
		}
		m.mu.Lock()
		_, dup := m.streams[sid]
		var s *stream
		if !dup {
			s = newStream(sid, m)
			m.streams[sid] = s
		}
		m.mu.Unlock()
		if s != nil && m.hooks.accept != nil {
			go m.hooks.accept(s)
		} else if s != nil {
			s.Close()
		}
	case opSynAck:
		m.mu.Lock()
		if m.watchdog != nil {
			m.watchdog.Stop()
			m.watchdog = nil
		}
		m.mu.Unlock()
		if len(body) > 0 {
			if s := m.lookup(sid); s != nil {
				s.shut(errRemote(string(body)), true)
			}
		}
	case opFin:
		m.mu.Lock()
		s := m.streams[sid]
		delete(m.streams, sid)
		m.mu.Unlock()
		if s != nil {
			s.shut(nil, false)
		}
	case opSettings:
		if m.client {
			return true
		}
		m.gotCfg = true
		peer := decodeKV(body)
		if peer["padding-md5"] != m.shape.sum {
			m.control(opScheme, 0, []byte(m.shape.text))
		}
		if v, err := strconv.Atoi(peer["v"]); err == nil && v >= 2 {
			m.peerVer.Store(int32(v))
			m.control(opServerSettings, 0, encodeKV("v", strconv.Itoa(protoVersion)))
		}
		if m.hooks.settings != nil {
			m.hooks.settings(peer)
		}
	case opServerSettings:
		if m.client {
			if v, err := strconv.Atoi(decodeKV(body)["v"]); err == nil {
				m.peerVer.Store(int32(v))
			}
		}
	case opAlert:
		if m.client && m.hooks.alert != nil {
			m.hooks.alert(string(body))
		}
		return false
	case opScheme:
		if m.client && m.hooks.scheme != nil {
			m.hooks.scheme(string(body))
		}
	case opBeat:
		m.control(opBeatAck, sid, nil)
	}
	return true
}

type errRemote string

func (e errRemote) Error() string { return "anytls: remote: " + string(e) }
