package vless

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/pion/turn/v4"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

type closerFunc func()

func (f closerFunc) Close() error { f(); return nil }

type xudpOptions struct {
	Server    string          `json:"server"`
	ID        string          `json:"id"`
	Transport string          `json:"transport,omitempty"`
	TLS       *tlsx.UClient   `json:"tls,omitempty"`
	DTLS      *DTLSClient     `json:"dtls,omitempty"`
	TURN      *TURN           `json:"turn,omitempty"`
	KeepAlive config.Duration `json:"keepalive,omitempty"`
	NoRetry   bool            `json:"no_reconnect,omitempty"`
}

type xudpConnector struct {
	env       *adapter.OutboundEnv
	server    addr.Addr
	id        UUID
	dtls      bool
	tls       tlsx.UClient
	dcfg      DTLSClient
	turn      *TURN
	keepalive time.Duration
	retry     bool
	header    []byte
	custom    func(ctx context.Context) (link, error)
}

func newXUDPConnector(env *adapter.OutboundEnv, o xudpOptions) (*xudpConnector, error) {
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("vless-xudp: bad server %q (want host:port)", o.Server)
	}
	id, err := ParseUUID(o.ID)
	if err != nil {
		return nil, fmt.Errorf("vless-xudp: %w", err)
	}
	c := &xudpConnector{env: env, server: server, id: id, turn: o.TURN, retry: !o.NoRetry}
	switch strings.ToLower(o.Transport) {
	case "", "tls":
		if o.DTLS != nil || o.TURN != nil {
			return nil, errors.New("vless-xudp: dtls and turn need transport \"dtls\"")
		}
		if o.TLS != nil {
			c.tls = *o.TLS
		}
		if err := c.tls.Validate(server.Host()); err != nil {
			return nil, fmt.Errorf("vless-xudp: %w", err)
		}
	case "dtls":
		if o.TLS != nil {
			return nil, errors.New("vless-xudp: tls does not apply to transport \"dtls\", use the dtls block")
		}
		c.dtls = true
		if o.DTLS != nil {
			c.dcfg = *o.DTLS
		}
		if _, err := c.dcfg.Config(server.Host()); err != nil {
			return nil, fmt.Errorf("vless-xudp: %w", err)
		}
		if o.TURN != nil {
			if err := o.TURN.Validate(); err != nil {
				return nil, fmt.Errorf("vless-xudp: %w", err)
			}
		}
	default:
		return nil, fmt.Errorf("vless-xudp: unknown transport %q (tls, dtls)", o.Transport)
	}
	c.keepalive = o.KeepAlive.Std()
	if c.keepalive <= 0 {
		c.keepalive = 20 * time.Second
	}
	hdr, err := appendRequest(nil, request{id: id, cmd: cmdMux})
	if err != nil {
		return nil, err
	}
	c.header = hdr
	return c, nil
}

func (c *xudpConnector) connect(ctx context.Context) (link, error) {
	if c.custom != nil {
		return c.custom(ctx)
	}
	if c.dtls {
		return c.connectDTLS(ctx)
	}
	return c.connectTLS(ctx)
}

func (c *xudpConnector) connectTLS(ctx context.Context) (link, error) {
	raw, err := c.env.Dialer.DialStream(ctx, c.server)
	if err != nil {
		return nil, err
	}
	hctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := c.tls.Handshake(hctx, raw, c.server.Host(), nil)
	if err != nil {
		raw.Close()
		return nil, err
	}
	l := newStreamLink(conn, nil, append([]byte(nil), c.header...))
	if err := l.flushHeader(); err != nil {
		conn.Close()
		return nil, err
	}
	return l, nil
}

func (c *xudpConnector) connectDTLS(ctx context.Context) (link, error) {
	cfg, err := c.dcfg.Config(c.server.Host())
	if err != nil {
		return nil, err
	}
	target := c.server
	if target.IsDomain() {
		ips, err := c.env.Resolver.Lookup(ctx, target.Host())
		if err != nil || len(ips) == 0 {
			return nil, fmt.Errorf("vless-xudp: resolve %s: %v", target.Host(), err)
		}
		target = addr.FromIP(ips[0], target.Port())
	}
	var (
		pc    net.PacketConn
		extra []io.Closer
	)
	if c.turn != nil {
		relay, tc, err := c.turn.allocate(ctx, c.env)
		if err != nil {
			return nil, err
		}
		pc = relay
		extra = append(extra, turnCloser(tc))
	} else if pc, err = c.env.Dialer.ListenPacket(ctx); err != nil {
		return nil, err
	}
	conn, err := dialDTLS(ctx, pc, target.UDPAddr(), cfg, c.dcfg.timeout(), extra...)
	if err != nil {
		return nil, err
	}
	hello := append([]byte{dgHello}, c.header...)
	deadline := time.Now().Add(c.dcfg.timeout())
	if dl, ok := ctx.Deadline(); ok && dl.Before(deadline) {
		deadline = dl
	}
	buf := make([]byte, 2048)
	for {
		if time.Now().After(deadline) || ctx.Err() != nil {
			conn.Close()
			return nil, errors.New("vless-xudp: no answer to hello over dtls")
		}
		if _, err := conn.Write(hello); err != nil {
			conn.Close()
			return nil, err
		}
		conn.SetReadDeadline(time.Now().Add(time.Second))
		n, err := conn.Read(buf)
		if err == nil && n >= 1 && buf[0] == dgHelloAck {
			break
		}
		var ne net.Error
		if err != nil && !(errors.As(err, &ne) && ne.Timeout()) {
			conn.Close()
			return nil, err
		}
	}
	conn.SetReadDeadline(time.Time{})
	l := newDgramLink(conn)
	l.idle = c.keepalive * 3
	return l, nil
}

func turnCloser(tc *turn.Client) io.Closer { return closerFunc(tc.Close) }

type xudpClient struct {
	c      *xudpConnector
	global [8]byte

	in   chan inPacket
	done chan struct{}
	once sync.Once
	dl   *deadline

	mu      sync.Mutex
	cur     link
	sentNew bool
}

func (c *xudpConnector) open(ctx context.Context) (adapter.PacketConn, error) {
	l, err := c.connect(ctx)
	if err != nil {
		return nil, err
	}
	x := &xudpClient{c: c, in: make(chan inPacket, 512), done: make(chan struct{}), dl: newDeadline()}
	rand.Read(x.global[:])
	if x.global == [8]byte{} {
		x.global[0] = 1
	}
	x.cur = l
	go x.supervise(l)
	return x, nil
}

func (x *xudpClient) supervise(l link) {
	backoff := time.Second
	for {
		x.mu.Lock()
		select {
		case <-x.done:
			x.mu.Unlock()
			l.close()
			return
		default:
		}
		if x.cur != l {
			x.cur, x.sentNew = l, false
		}
		x.mu.Unlock()
		started := time.Now()
		x.pump(l)
		x.mu.Lock()
		if x.cur == l {
			x.cur = nil
		}
		x.mu.Unlock()
		l.close()
		if !x.c.retry {
			x.Close()
			return
		}
		if time.Since(started) > 30*time.Second {
			backoff = time.Second
		}
		for {
			select {
			case <-x.done:
				return
			case <-time.After(backoff):
			}
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			nl, err := x.c.connect(ctx)
			cancel()
			if err == nil {
				l = nl
				break
			}
			backoff = min(backoff*2, 15*time.Second)
		}
	}
}

func (x *xudpClient) pump(l link) {
	stop := make(chan struct{})
	defer close(stop)
	go func() {
		t := time.NewTicker(x.c.keepalive)
		defer t.Stop()
		for {
			select {
			case <-stop:
				return
			case <-x.done:
				l.close()
				return
			case <-t.C:
				if l.send(frame{status: stKeepAlive}) != nil {
					l.close()
					return
				}
			}
		}
	}()
	if sl, ok := l.(*streamLink); ok {
		if err := skipResponseHeader(sl.r); err != nil {
			return
		}
	}
	for {
		f, err := l.recv()
		if err != nil {
			return
		}
		switch f.status {
		case stKeep:
			if f.hasData() {
				select {
				case x.in <- inPacket{data: f.data, peer: f.dest}:
				default:
				}
			}
		case stEnd:
			return
		}
	}
}

func (x *xudpClient) ReadPacket(p []byte) (int, addr.Addr, error) {
	select {
	case <-x.done:
		return 0, addr.Addr{}, errClosed
	default:
	}
	select {
	case pk := <-x.in:
		return copy(p, pk.data), pk.peer, nil
	case <-x.done:
		return 0, addr.Addr{}, errClosed
	case <-x.dl.wait():
		return 0, addr.Addr{}, timeoutError{}
	}
}

func (x *xudpClient) WritePacket(p []byte, peer addr.Addr) error {
	select {
	case <-x.done:
		return errClosed
	default:
	}
	x.mu.Lock()
	defer x.mu.Unlock()
	l := x.cur
	if l == nil {
		return nil
	}
	f := frame{status: stKeep, option: optData, dest: peer, data: p}
	if !x.sentNew {
		f.status, f.network, f.global = stNew, netUDP, x.global
	}
	if err := l.send(f); err != nil {
		if errors.Is(err, errTooLarge) {
			return err
		}
		l.close()
		return nil
	}
	x.sentNew = true
	return nil
}

func (x *xudpClient) SetReadDeadline(t time.Time) error {
	x.dl.set(t)
	return nil
}

func (x *xudpClient) Close() error {
	x.once.Do(func() {
		close(x.done)
		x.mu.Lock()
		l := x.cur
		x.mu.Unlock()
		if l != nil {
			l.send(frame{status: stEnd})
			l.close()
		}
	})
	return nil
}
