package juicity

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	maxSessions    = 8
	dialPatience   = 12 * time.Second
	backoffStart   = 200 * time.Millisecond
	backoffCeiling = 5 * time.Second
)

type session struct {
	conn *quic.Conn
	tr   *quic.Transport
	pc   net.PacketConn
}

func (s *session) shutdown(code quic.ApplicationErrorCode) {
	s.conn.CloseWithError(code, "")
	s.tr.Close()
	s.pc.Close()
}

type attempt struct {
	done chan struct{}
	err  error
}

type manager struct {
	establish func(ctx context.Context) (*session, error)

	mu       sync.Mutex
	sessions []*session
	building *attempt
	closed   bool
	failErr  error
	retryAt  time.Time
	backoff  time.Duration
}

var errClosed = errors.New("juicity: outbound closed")

func (m *manager) open(ctx context.Context) (*quic.Stream, *quic.Conn, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, nil, errClosed
		}
		m.prune()
		for i := len(m.sessions) - 1; i >= 0; i-- {
			st, err := m.sessions[i].conn.OpenStream()
			if err == nil {
				c := m.sessions[i].conn
				m.mu.Unlock()
				return st, c, nil
			}
		}
		if len(m.sessions) >= maxSessions {
			last := m.sessions[len(m.sessions)-1].conn
			m.mu.Unlock()
			st, err := last.OpenStreamSync(ctx)
			return st, last, err
		}
		if m.building == nil {
			if wait := time.Until(m.retryAt); wait > 0 && m.failErr != nil {
				err := m.failErr
				m.mu.Unlock()
				return nil, nil, err
			}
			m.building = &attempt{done: make(chan struct{})}
			go m.build(m.building)
		}
		at := m.building
		m.mu.Unlock()
		select {
		case <-at.done:
			if at.err != nil {
				return nil, nil, at.err
			}
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}
}

func (m *manager) prune() {
	live := m.sessions[:0]
	for _, s := range m.sessions {
		if s.conn.Context().Err() == nil {
			live = append(live, s)
		}
	}
	for i := len(live); i < len(m.sessions); i++ {
		m.sessions[i] = nil
	}
	m.sessions = live
}

func (m *manager) build(at *attempt) {
	ctx, cancel := context.WithTimeout(context.Background(), dialPatience)
	defer cancel()
	s, err := m.establish(ctx)
	m.mu.Lock()
	defer m.mu.Unlock()
	m.building = nil
	switch {
	case err != nil:
		m.failErr = err
		m.backoff = min(max(m.backoff*2, backoffStart), backoffCeiling)
		m.retryAt = time.Now().Add(m.backoff)
		at.err = err
	case m.closed:
		s.shutdown(0)
		at.err = errClosed
	default:
		m.failErr, m.backoff = nil, 0
		m.sessions = append(m.sessions, s)
	}
	close(at.done)
}

func (m *manager) shutdown() {
	m.mu.Lock()
	m.closed = true
	ss := m.sessions
	m.sessions = nil
	m.mu.Unlock()
	for _, s := range ss {
		s.shutdown(0)
	}
}
