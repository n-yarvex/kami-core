package anytls

import (
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/bufpool"
)

const inboxLimit = 256 << 10

var (
	errStreamClosed = errors.New("anytls: stream closed")
	errSessionDead  = errors.New("anytls: session closed")
)

type inbox struct {
	mu     sync.Mutex
	chunks [][]byte
	size   int
	eof    bool
	err    error
	ready  chan struct{}
	space  chan struct{}
}

func newInbox() *inbox {
	return &inbox{ready: make(chan struct{}, 1), space: make(chan struct{}, 1)}
}

func poke(c chan struct{}) {
	select {
	case c <- struct{}{}:
	default:
	}
}

func (b *inbox) push(data []byte, dead <-chan struct{}) bool {
	for {
		b.mu.Lock()
		if b.eof || b.err != nil {
			b.mu.Unlock()
			return false
		}
		if b.size < inboxLimit {
			chunk := bufpool.Get(len(data))
			copy(chunk, data)
			b.chunks = append(b.chunks, chunk[:len(data)])
			b.size += len(data)
			b.mu.Unlock()
			poke(b.ready)
			return true
		}
		b.mu.Unlock()
		select {
		case <-b.space:
		case <-dead:
			return false
		}
	}
}

func (b *inbox) take(p []byte) (int, error, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if len(b.chunks) > 0 {
		n := copy(p, b.chunks[0])
		b.chunks[0] = b.chunks[0][n:]
		b.size -= n
		if len(b.chunks[0]) == 0 {
			b.chunks[0] = nil
			b.chunks = b.chunks[1:]
		}
		poke(b.space)
		return n, nil, true
	}
	switch {
	case b.err != nil:
		return 0, b.err, true
	case b.eof:
		return 0, io.EOF, true
	}
	return 0, nil, false
}

func (b *inbox) finish(err error) {
	b.mu.Lock()
	if err != nil && b.err == nil {
		b.err = err
		b.chunks, b.size = nil, 0
	} else if err == nil {
		b.eof = true
	}
	b.mu.Unlock()
	poke(b.ready)
	poke(b.space)
}

type stream struct {
	id   uint32
	mux  *mux
	in   *inbox
	rdl  *deadline
	wdl  *deadline
	once sync.Once
	hook func()
	werr error
	mu   sync.Mutex
}

func newStream(id uint32, m *mux) *stream {
	return &stream{id: id, mux: m, in: newInbox(), rdl: newDeadline(), wdl: newDeadline()}
}

func (s *stream) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	for {
		n, err, ok := s.in.take(p)
		if ok {
			return n, err
		}
		select {
		case <-s.in.ready:
		case <-s.rdl.wait():
			return 0, errTimeout
		case <-s.mux.dead:
			if n, err, ok := s.in.take(p); ok {
				return n, err
			}
			return 0, errSessionDead
		}
	}
}

func (s *stream) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	done := 0
	for done < len(p) {
		select {
		case <-s.wdl.wait():
			return done, errTimeout
		default:
		}
		s.mu.Lock()
		werr := s.werr
		s.mu.Unlock()
		if werr != nil {
			return done, werr
		}
		n := min(len(p)-done, maxBody)
		if err := s.mux.push(s.id, p[done:done+n]); err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

func (s *stream) shut(err error, notify bool) {
	s.once.Do(func() {
		s.mu.Lock()
		if err == nil {
			s.werr = errStreamClosed
		} else {
			s.werr = err
		}
		s.mu.Unlock()
		s.in.finish(err)
		if notify {
			s.mux.fin(s.id)
		}
		if s.hook != nil {
			s.hook()
		}
	})
}

func (s *stream) Close() error {
	s.shut(nil, true)
	s.in.mu.Lock()
	s.in.eof = true
	for _, c := range s.in.chunks {
		bufpool.Put(c[:cap(c)])
	}
	s.in.chunks, s.in.size = nil, 0
	s.in.mu.Unlock()
	poke(s.in.space)
	return nil
}

func (s *stream) CloseWrite() error {
	if s.mux.client {
		return errors.New("anytls: half close unsupported")
	}
	return s.Close()
}

func (s *stream) LocalAddr() net.Addr  { return s.mux.conn.LocalAddr() }
func (s *stream) RemoteAddr() net.Addr { return s.mux.conn.RemoteAddr() }

func (s *stream) SetDeadline(t time.Time) error {
	s.rdl.set(t)
	s.wdl.set(t)
	return nil
}

func (s *stream) SetReadDeadline(t time.Time) error  { s.rdl.set(t); return nil }
func (s *stream) SetWriteDeadline(t time.Time) error { s.wdl.set(t); return nil }
