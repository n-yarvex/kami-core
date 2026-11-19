package masque

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	maxSessions    = 8
	dialPatience   = 12 * time.Second
	backoffStart   = 200 * time.Millisecond
	backoffCeiling = 5 * time.Second
)

var (
	errClosed = errors.New("masque: outbound closed")
	errFull   = errors.New("masque: connection stream limit reached")
)

type session struct {
	conn *quic.Conn
	cc   *http3.ClientConn
	tr   *quic.Transport
	pc   net.PacketConn
	ext  bool
	dg   bool
}

func (s *session) shutdown() {
	s.conn.CloseWithError(0, "")
	s.tr.Close()
	s.pc.Close()
}

func (s *session) probe(ctx context.Context) (*http3.RequestStream, error) {
	pctx, cancel := context.WithTimeout(ctx, probeWait)
	defer cancel()
	rs, err := s.cc.OpenRequestStream(pctx)
	if err == nil {
		return rs, nil
	}
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return nil, errFull
	}
	return nil, err
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

func (m *manager) open(ctx context.Context) (*http3.RequestStream, *session, error) {
	for {
		m.mu.Lock()
		if m.closed {
			m.mu.Unlock()
			return nil, nil, errClosed
		}
		m.prune()
		snapshot := append([]*session(nil), m.sessions...)
		m.mu.Unlock()
		for i := len(snapshot) - 1; i >= 0; i-- {
			rs, err := snapshot[i].probe(ctx)
			if err == nil {
				return rs, snapshot[i], nil
			}
			if ctx.Err() != nil {
				return nil, nil, ctx.Err()
			}
		}
		m.mu.Lock()
		if len(m.sessions) >= maxSessions {
			last := m.sessions[len(m.sessions)-1]
			m.mu.Unlock()
			rs, err := last.cc.OpenRequestStream(ctx)
			return rs, last, err
		}
		if m.building == nil {
			if time.Until(m.retryAt) > 0 && m.failErr != nil {
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
		s.shutdown()
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
		s.shutdown()
	}
}
