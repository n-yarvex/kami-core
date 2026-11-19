package anytls

import (
	"os"
	"sync"
	"time"
)

type gate struct {
	ch   chan struct{}
	once sync.Once
}

func newGate() *gate { return &gate{ch: make(chan struct{})} }

func (g *gate) trip() { g.once.Do(func() { close(g.ch) }) }

func (g *gate) tripped() bool { return isClosed(g.ch) }

type deadline struct {
	mu    sync.Mutex
	cur   *gate
	timer *time.Timer
}

func newDeadline() *deadline { return &deadline{cur: newGate()} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil {
		d.timer.Stop()
		d.timer = nil
	}
	if d.cur.tripped() {
		d.cur = newGate()
	}
	if t.IsZero() {
		return
	}
	g := d.cur
	wait := time.Until(t)
	if wait <= 0 {
		g.trip()
		return
	}
	d.timer = time.AfterFunc(wait, g.trip)
}

func (d *deadline) wait() <-chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cur.ch
}

var errTimeout error = os.ErrDeadlineExceeded

func isClosed(c <-chan struct{}) (closed bool) {
	select {
	case <-c:
		closed = true
	default:
	}
	return
}
