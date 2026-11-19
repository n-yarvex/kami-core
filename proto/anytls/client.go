package anytls

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"log/slog"
	"net"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n-yarvex/kami-core/addr"
)

const sessionDialBudget = 20 * time.Second

type pool struct {
	dial  func(ctx context.Context) (net.Conn, error)
	key   [sha256.Size]byte
	shape atomic.Pointer[scheme]
	log   *slog.Logger

	every   time.Duration
	timeout time.Duration
	keep    int

	ctx    context.Context
	cancel context.CancelFunc

	mu     sync.Mutex
	idle   []*mux
	live   map[*mux]struct{}
	serial uint64
	freed  chan struct{}
}

func newPool(dial func(context.Context) (net.Conn, error), password string, every, timeout time.Duration, keep int, log *slog.Logger) *pool {
	ctx, cancel := context.WithCancel(context.Background())
	p := &pool{
		dial:    dial,
		key:     sha256.Sum256([]byte(password)),
		log:     log,
		every:   every,
		timeout: timeout,
		keep:    keep,
		ctx:     ctx,
		cancel:  cancel,
		live:    map[*mux]struct{}{},
		freed:   make(chan struct{}),
	}
	p.shape.Store(builtinScheme)
	go p.sweep()
	return p
}

func (p *pool) newSession(ctx context.Context) (*mux, error) {
	conn, err := p.dial(ctx)
	if err != nil {
		return nil, err
	}
	shape := p.shape.Load()
	pad := shape.authPadding()
	hello := make([]byte, 0, len(p.key)+2+pad)
	hello = append(hello, p.key[:]...)
	hello = binary.BigEndian.AppendUint16(hello, uint16(pad))
	hello = append(hello, make([]byte, pad)...)
	rand.Read(hello[len(hello)-pad:])
	conn.SetWriteDeadline(time.Now().Add(writeStall))
	if _, err := conn.Write(hello); err != nil {
		conn.Close()
		return nil, err
	}
	m := newMux(conn, true, shape, muxHooks{
		scheme: p.adopt,
		alert: func(text string) {
			p.log.Warn("anytls server alert", "text", text)
		},
	})
	p.mu.Lock()
	p.serial++
	m.seq = p.serial
	p.live[m] = struct{}{}
	m.dieHook = func() { p.forget(m) }
	p.mu.Unlock()
	go m.serve()
	if err := m.hello(); err != nil {
		m.kill()
		return nil, err
	}
	return m, nil
}

func (p *pool) adopt(raw string) {
	s, err := parseScheme(raw)
	if err != nil {
		p.log.Warn("ignored padding scheme from server", "err", err)
		return
	}
	p.shape.Store(s)
	p.log.Debug("padding scheme updated", "md5", s.sum)
}

func (p *pool) forget(m *mux) {
	p.mu.Lock()
	delete(p.live, m)
	for i, x := range p.idle {
		if x == m {
			p.idle = append(p.idle[:i], p.idle[i+1:]...)
			break
		}
	}
	p.mu.Unlock()
}

func (p *pool) release(m *mux) {
	if !m.alive() {
		return
	}
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		m.kill()
		return
	}
	m.idleSince = time.Now()
	p.idle = append(p.idle, m)
	sort.Slice(p.idle, func(i, j int) bool { return p.idle[i].seq < p.idle[j].seq })
	old := p.freed
	p.freed = make(chan struct{})
	p.mu.Unlock()
	close(old)
}

func (p *pool) takeIdle() *mux {
	p.mu.Lock()
	defer p.mu.Unlock()
	for len(p.idle) > 0 {
		m := p.idle[len(p.idle)-1]
		p.idle = p.idle[:len(p.idle)-1]
		if m.alive() {
			return m
		}
	}
	return nil
}

func (p *pool) signal() <-chan struct{} {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.freed
}

type fresh struct {
	m   *mux
	err error
}

func (p *pool) acquire(ctx context.Context) (*mux, error) {
	for {
		if m := p.takeIdle(); m != nil {
			return m, nil
		}
		wake := p.signal()
		if m := p.takeIdle(); m != nil {
			return m, nil
		}
		dctx, cancel := context.WithTimeout(p.ctx, sessionDialBudget)
		out := make(chan fresh, 1)
		go func() {
			defer cancel()
			m, err := p.newSession(dctx)
			out <- fresh{m, err}
		}()
		select {
		case r := <-out:
			return r.m, r.err
		case <-wake:
			go p.adoptLate(out)
		case <-ctx.Done():
			go p.adoptLate(out)
			return nil, ctx.Err()
		case <-p.ctx.Done():
			go p.adoptLate(out)
			return nil, errors.New("anytls: client closed")
		}
	}
}

func (p *pool) adoptLate(out <-chan fresh) {
	if r := <-out; r.err == nil {
		p.release(r.m)
	}
}

func (p *pool) open(ctx context.Context) (*stream, error) {
	var last error
	for try := 0; try < 3; try++ {
		m, err := p.acquire(ctx)
		if err != nil {
			return nil, err
		}
		s, err := m.open()
		if err != nil {
			m.kill()
			last = err
			continue
		}
		s.hook = func() { p.release(m) }
		return s, nil
	}
	return nil, last
}

func (p *pool) dialStream(ctx context.Context, dest addr.Addr) (*stream, error) {
	target, err := dest.AppendSocks(nil)
	if err != nil {
		return nil, err
	}
	s, err := p.open(ctx)
	if err != nil {
		return nil, err
	}
	if _, err := s.Write(target); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

func (p *pool) sweep() {
	tick := time.NewTicker(p.every)
	defer tick.Stop()
	for {
		select {
		case <-p.ctx.Done():
			return
		case now := <-tick.C:
			var stale []*mux
			p.mu.Lock()
			for len(p.idle) > p.keep && now.Sub(p.idle[0].idleSince) > p.timeout {
				stale = append(stale, p.idle[0])
				p.idle = p.idle[1:]
			}
			p.mu.Unlock()
			for _, m := range stale {
				m.kill()
			}
		}
	}
}

func (p *pool) close() {
	p.cancel()
	p.mu.Lock()
	all := make([]*mux, 0, len(p.live))
	for m := range p.live {
		all = append(all, m)
	}
	p.mu.Unlock()
	for _, m := range all {
		m.kill()
	}
}
