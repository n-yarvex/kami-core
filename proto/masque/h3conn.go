package masque

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const codeConnect = quic.StreamErrorCode(http3.ErrCodeConnectError)

type h3Stream interface {
	Read([]byte) (int, error)
	Write([]byte) (int, error)
	Close() error
	CancelRead(quic.StreamErrorCode)
	CancelWrite(quic.StreamErrorCode)
	SetDeadline(time.Time) error
	SetReadDeadline(time.Time) error
	SetWriteDeadline(time.Time) error
	SendDatagram([]byte) error
	ReceiveDatagram(context.Context) ([]byte, error)
}

type streamConn struct {
	mu     sync.Mutex
	st     h3Stream
	ready  chan struct{}
	once   sync.Once
	local  net.Addr
	remote net.Addr
}

func newStreamConn(st h3Stream, local, remote net.Addr) *streamConn {
	c := &streamConn{st: st, ready: make(chan struct{}), local: local, remote: remote}
	if st != nil {
		c.once.Do(func() { close(c.ready) })
	}
	return c
}

func (c *streamConn) bind(st h3Stream) {
	c.mu.Lock()
	c.st = st
	c.mu.Unlock()
	c.once.Do(func() { close(c.ready) })
}

func (c *streamConn) abandon() {
	c.once.Do(func() { close(c.ready) })
}

func (c *streamConn) stream() (h3Stream, error) {
	<-c.ready
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.st == nil {
		return nil, net.ErrClosed
	}
	return c.st, nil
}

func (c *streamConn) Read(p []byte) (int, error) {
	st, err := c.stream()
	if err != nil {
		return 0, err
	}
	return st.Read(p)
}

func (c *streamConn) Write(p []byte) (int, error) {
	st, err := c.stream()
	if err != nil {
		return 0, err
	}
	return st.Write(p)
}

func (c *streamConn) CloseWrite() error {
	st, err := c.stream()
	if err != nil {
		return err
	}
	return st.Close()
}

func (c *streamConn) Close() error {
	c.abandon()
	c.mu.Lock()
	st := c.st
	c.mu.Unlock()
	if st == nil {
		return nil
	}
	st.CancelRead(codeConnect)
	return st.Close()
}

func (c *streamConn) LocalAddr() net.Addr  { return c.local }
func (c *streamConn) RemoteAddr() net.Addr { return c.remote }

func (c *streamConn) deadline(f func(h3Stream, time.Time) error, t time.Time) error {
	c.mu.Lock()
	st := c.st
	c.mu.Unlock()
	if st == nil {
		return nil
	}
	return f(st, t)
}

func (c *streamConn) SetDeadline(t time.Time) error {
	return c.deadline(func(s h3Stream, t time.Time) error { return s.SetDeadline(t) }, t)
}

func (c *streamConn) SetReadDeadline(t time.Time) error {
	return c.deadline(func(s h3Stream, t time.Time) error { return s.SetReadDeadline(t) }, t)
}

func (c *streamConn) SetWriteDeadline(t time.Time) error {
	return c.deadline(func(s h3Stream, t time.Time) error { return s.SetWriteDeadline(t) }, t)
}
