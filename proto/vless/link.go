package vless

import (
	"bufio"
	"bytes"
	"errors"
	"net"
	"sync"
	"time"
)

const (
	dgHello    = 1
	dgHelloAck = 2
	dgFrames   = 3
)

type link interface {
	send(f frame) error
	recv() (frame, error)
	close() error
	remote() net.Addr
}

type streamLink struct {
	conn    net.Conn
	r       *bufio.Reader
	mu      sync.Mutex
	pending []byte
}

func newStreamLink(conn net.Conn, r *bufio.Reader, pendingHeader []byte) *streamLink {
	if r == nil {
		r = bufio.NewReaderSize(conn, 8192)
	}
	return &streamLink{conn: conn, r: r, pending: pendingHeader}
}

func (l *streamLink) send(f frame) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	b := l.pending
	l.pending = nil
	b, err := appendFrame(b, f)
	if err != nil {
		return err
	}
	_, err = l.conn.Write(b)
	return err
}

func (l *streamLink) flushHeader() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.pending) == 0 {
		return nil
	}
	b := l.pending
	l.pending = nil
	_, err := l.conn.Write(b)
	return err
}

func (l *streamLink) recv() (frame, error) { return readFrame(l.r) }
func (l *streamLink) close() error         { return l.conn.Close() }
func (l *streamLink) remote() net.Addr     { return l.conn.RemoteAddr() }

type dgramLink struct {
	conn  net.Conn
	mu    sync.Mutex
	queue *bytes.Reader
	buf   []byte

	onHello func()
	idle    time.Duration
}

func newDgramLink(conn net.Conn) *dgramLink {
	return &dgramLink{conn: conn, buf: make([]byte, 65535+1024)}
}

func (l *dgramLink) send(f frame) error {
	b, err := appendFrame([]byte{dgFrames}, f)
	if err != nil {
		return err
	}
	_, err = l.conn.Write(b)
	return err
}

func (l *dgramLink) recv() (frame, error) {
	for {
		if l.queue != nil && l.queue.Len() > 0 {
			f, err := readFrame(l.queue)
			if err != nil {
				l.queue = nil
				continue
			}
			return f, nil
		}
		l.queue = nil
		if l.idle > 0 {
			l.conn.SetReadDeadline(time.Now().Add(l.idle))
		}
		n, err := l.conn.Read(l.buf)
		if err != nil {
			return frame{}, err
		}
		if n < 1 {
			continue
		}
		switch l.buf[0] {
		case dgFrames:
			l.queue = bytes.NewReader(append([]byte(nil), l.buf[1:n]...))
		case dgHello:
			if l.onHello != nil {
				l.onHello()
			}
		}
	}
}

func (l *dgramLink) close() error     { return l.conn.Close() }
func (l *dgramLink) remote() net.Addr { return l.conn.RemoteAddr() }

var errClosed = errors.New("vless: closed")

type deadline struct {
	mu     sync.Mutex
	timer  *time.Timer
	cancel chan struct{}
}

func newDeadline() *deadline { return &deadline{cancel: make(chan struct{})} }

func (d *deadline) set(t time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.timer != nil && !d.timer.Stop() {
		<-d.cancel
	}
	d.timer = nil
	closed := isClosed(d.cancel)
	if t.IsZero() {
		if closed {
			d.cancel = make(chan struct{})
		}
		return
	}
	if dur := time.Until(t); dur > 0 {
		if closed {
			d.cancel = make(chan struct{})
		}
		c := d.cancel
		d.timer = time.AfterFunc(dur, func() { close(c) })
		return
	}
	if !closed {
		close(d.cancel)
	}
}

func (d *deadline) wait() chan struct{} {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.cancel
}

func isClosed(c chan struct{}) bool {
	select {
	case <-c:
		return true
	default:
		return false
	}
}
