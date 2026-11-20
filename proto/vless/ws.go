package vless

import (
	"io"
	"net"
	"sync"
	"time"

	"github.com/gorilla/websocket"
)

type wsConn struct {
	c      *websocket.Conn
	rmu    sync.Mutex
	rd     io.Reader
	wmu    sync.Mutex
	local  net.Addr
	remote net.Addr
}

func newWSConn(c *websocket.Conn) *wsConn {
	return &wsConn{c: c, local: c.LocalAddr(), remote: c.RemoteAddr()}
}

func (w *wsConn) Read(p []byte) (int, error) {
	w.rmu.Lock()
	defer w.rmu.Unlock()
	for {
		if w.rd == nil {
			mt, r, err := w.c.NextReader()
			if err != nil {
				if websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway, websocket.CloseNoStatusReceived) {
					return 0, io.EOF
				}
				return 0, err
			}
			if mt != websocket.BinaryMessage {
				continue
			}
			w.rd = r
		}
		n, err := w.rd.Read(p)
		if err == io.EOF {
			w.rd = nil
			if n > 0 {
				return n, nil
			}
			continue
		}
		return n, err
	}
}

func (w *wsConn) Write(p []byte) (int, error) {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	if err := w.c.WriteMessage(websocket.BinaryMessage, p); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (w *wsConn) ping() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteControl(websocket.PingMessage, nil, time.Now().Add(10*time.Second))
}

func (w *wsConn) CloseWrite() error {
	w.wmu.Lock()
	defer w.wmu.Unlock()
	return w.c.WriteControl(websocket.CloseMessage,
		websocket.FormatCloseMessage(websocket.CloseNormalClosure, ""), time.Now().Add(5*time.Second))
}

func (w *wsConn) Close() error         { return w.c.Close() }
func (w *wsConn) LocalAddr() net.Addr  { return w.local }
func (w *wsConn) RemoteAddr() net.Addr { return w.remote }
func (w *wsConn) SetDeadline(t time.Time) error {
	w.c.SetReadDeadline(t)
	return w.c.SetWriteDeadline(t)
}
func (w *wsConn) SetReadDeadline(t time.Time) error  { return w.c.SetReadDeadline(t) }
func (w *wsConn) SetWriteDeadline(t time.Time) error { return w.c.SetWriteDeadline(t) }

func (w *wsConn) keepalive(every time.Duration, done <-chan struct{}) {
	if every <= 0 {
		return
	}
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-done:
			return
		case <-t.C:
			if w.ping() != nil {
				return
			}
		}
	}
}
