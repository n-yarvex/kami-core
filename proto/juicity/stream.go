package juicity

import (
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
)

type tcpConn struct {
	s      *quic.Stream
	rd     io.Reader
	local  net.Addr
	remote net.Addr

	pending atomic.Bool
	mu      sync.Mutex
	head    []byte
	timer   *time.Timer
}

func newTCPConn(s *quic.Stream, rd io.Reader, local, remote net.Addr) *tcpConn {
	c := &tcpConn{s: s, rd: rd, local: local, remote: remote}
	if c.rd == nil {
		c.rd = s
	}
	return c
}

func (c *tcpConn) holdHeader(h []byte, wait time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.head = h
	c.pending.Store(true)
	c.timer = time.AfterFunc(wait, func() { c.flushHeader() })
}

func (c *tcpConn) flushHeader() error {
	if !c.pending.Load() {
		return nil
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.head == nil {
		return nil
	}
	h := c.head
	c.head = nil
	c.pending.Store(false)
	c.timer.Stop()
	_, err := c.s.Write(h)
	return err
}

func (c *tcpConn) Write(p []byte) (int, error) {
	if c.pending.Load() {
		c.mu.Lock()
		if h := c.head; h != nil {
			c.head = nil
			c.pending.Store(false)
			c.timer.Stop()
			n, err := c.s.Write(append(h, p...))
			c.mu.Unlock()
			return max(n-len(h), 0), err
		}
		c.mu.Unlock()
	}
	return c.s.Write(p)
}

func (c *tcpConn) Read(p []byte) (int, error) { return c.rd.Read(p) }

func (c *tcpConn) CloseWrite() error {
	if err := c.flushHeader(); err != nil {
		return err
	}
	return c.s.Close()
}

func (c *tcpConn) Close() error {
	c.mu.Lock()
	if c.timer != nil {
		c.timer.Stop()
	}
	c.mu.Unlock()
	c.s.CancelRead(0)
	return c.s.Close()
}

func (c *tcpConn) LocalAddr() net.Addr                { return c.local }
func (c *tcpConn) RemoteAddr() net.Addr               { return c.remote }
func (c *tcpConn) SetDeadline(t time.Time) error      { return c.s.SetDeadline(t) }
func (c *tcpConn) SetReadDeadline(t time.Time) error  { return c.s.SetReadDeadline(t) }
func (c *tcpConn) SetWriteDeadline(t time.Time) error { return c.s.SetWriteDeadline(t) }

type idler struct {
	last  atomic.Int64
	span  time.Duration
	timer *time.Timer
	fire  func()
}

func newIdler(span time.Duration, fire func()) *idler {
	i := &idler{span: span, fire: fire}
	i.last.Store(time.Now().UnixNano())
	i.timer = time.AfterFunc(span, i.check)
	return i
}

func (i *idler) touch() { i.last.Store(time.Now().UnixNano()) }

func (i *idler) check() {
	left := i.span - time.Duration(time.Now().UnixNano()-i.last.Load())
	if left > 0 {
		i.timer.Reset(left)
		return
	}
	i.fire()
}

func (i *idler) stop() { i.timer.Stop() }
