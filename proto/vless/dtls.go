package vless

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/pion/dtls/v3"

	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

type dtlsCommon struct {
	CipherSuites         []string        `json:"cipher_suites,omitempty"`
	FlightInterval       config.Duration `json:"flight_interval,omitempty"`
	MTU                  int             `json:"mtu,omitempty"`
	ExtendedMasterSecret string          `json:"extended_master_secret,omitempty"`
	ReplayWindow         int             `json:"replay_window,omitempty"`
	HandshakeTimeout     config.Duration `json:"handshake_timeout,omitempty"`
	PSK                  string          `json:"psk,omitempty"`
	PSKIdentity          string          `json:"psk_identity,omitempty"`
}

type DTLSClient struct {
	tlsx.Client
	dtlsCommon
}

type DTLSServer struct {
	tlsx.Server
	dtlsCommon
	ClientAuth string   `json:"client_auth,omitempty"`
	ClientCA   []string `json:"client_ca,omitempty"`
}

var cipherIDs = []dtls.CipherSuiteID{
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_CCM_8,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
	dtls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
	dtls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
	dtls.TLS_ECDHE_ECDSA_WITH_AES_256_CBC_SHA,
	dtls.TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA,
	dtls.TLS_PSK_WITH_AES_128_CCM,
	dtls.TLS_PSK_WITH_AES_128_CCM_8,
	dtls.TLS_PSK_WITH_AES_256_CCM_8,
	dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
	dtls.TLS_PSK_WITH_AES_128_CBC_SHA256,
	dtls.TLS_ECDHE_PSK_WITH_AES_128_CBC_SHA256,
	dtls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
	dtls.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
}

func CipherSuiteNames() []string {
	out := make([]string, 0, len(cipherIDs))
	for _, id := range cipherIDs {
		out = append(out, dtls.CipherSuiteName(id))
	}
	return out
}

func (c dtlsCommon) apply(cfg *dtls.Config, server bool) error {
	for _, name := range c.CipherSuites {
		found := false
		for _, id := range cipherIDs {
			if strings.EqualFold(dtls.CipherSuiteName(id), strings.TrimSpace(name)) {
				cfg.CipherSuites = append(cfg.CipherSuites, id)
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("dtls: unknown cipher suite %q (known: %s)", name, strings.Join(CipherSuiteNames(), ", "))
		}
	}
	if len(cfg.CipherSuites) == 0 && c.PSK != "" {
		cfg.CipherSuites = []dtls.CipherSuiteID{
			dtls.TLS_ECDHE_PSK_WITH_CHACHA20_POLY1305_SHA256,
			dtls.TLS_PSK_WITH_AES_128_GCM_SHA256,
			dtls.TLS_PSK_WITH_CHACHA20_POLY1305_SHA256,
			dtls.TLS_PSK_WITH_AES_128_CCM,
		}
	}
	cfg.FlightInterval = c.FlightInterval.Std()
	if c.MTU != 0 {
		if c.MTU < 576 || c.MTU > 65000 {
			return errors.New("dtls: mtu must be between 576 and 65000")
		}
		cfg.MTU = c.MTU
	}
	if c.ReplayWindow < 0 {
		return errors.New("dtls: replay_window must not be negative")
	}
	cfg.ReplayProtectionWindow = c.ReplayWindow
	switch strings.ToLower(c.ExtendedMasterSecret) {
	case "", "request":
		cfg.ExtendedMasterSecret = dtls.RequestExtendedMasterSecret
	case "require":
		cfg.ExtendedMasterSecret = dtls.RequireExtendedMasterSecret
	case "disable":
		cfg.ExtendedMasterSecret = dtls.DisableExtendedMasterSecret
	default:
		return fmt.Errorf("dtls: unknown extended_master_secret %q (request, require, disable)", c.ExtendedMasterSecret)
	}
	if c.PSK != "" {
		key := []byte(c.PSK)
		identity := c.PSKIdentity
		cfg.PSK = func(hint []byte) ([]byte, error) {
			if server && identity != "" && string(hint) != identity {
				return nil, errors.New("dtls: unexpected psk identity")
			}
			return key, nil
		}
		cfg.PSKIdentityHint = []byte(identity)
		if !server && cfg.PSKIdentityHint == nil {
			cfg.PSKIdentityHint = []byte{}
		}
	} else if c.PSKIdentity != "" {
		return errors.New("dtls: psk_identity needs psk")
	}
	return nil
}

func (c DTLSClient) timeout() time.Duration {
	if d := c.HandshakeTimeout.Std(); d > 0 {
		return d
	}
	return 15 * time.Second
}

func (c DTLSClient) Config(host string) (*dtls.Config, error) {
	cfg := &dtls.Config{}
	if err := c.dtlsCommon.apply(cfg, false); err != nil {
		return nil, err
	}
	if c.PSK != "" {
		cfg.ServerName = c.ServerName
		return cfg, nil
	}
	tc, err := c.Client.Config(host)
	if err != nil {
		return nil, err
	}
	cfg.ServerName = tc.ServerName
	cfg.InsecureSkipVerify = tc.InsecureSkipVerify
	cfg.RootCAs = tc.RootCAs
	cfg.VerifyPeerCertificate = tc.VerifyPeerCertificate
	return cfg, nil
}

func (s DTLSServer) timeout() time.Duration {
	if d := s.HandshakeTimeout.Std(); d > 0 {
		return d
	}
	return 15 * time.Second
}

func (s DTLSServer) Config() (*dtls.Config, error) {
	cfg := &dtls.Config{}
	if err := s.dtlsCommon.apply(cfg, true); err != nil {
		return nil, err
	}
	if s.PSK == "" {
		tc, err := s.Server.Config()
		if err != nil {
			return nil, err
		}
		cfg.GetCertificate = func(*dtls.ClientHelloInfo) (*tls.Certificate, error) {
			if tc.GetCertificate != nil {
				return tc.GetCertificate(nil)
			}
			return &tc.Certificates[0], nil
		}
	}
	switch strings.ToLower(s.ClientAuth) {
	case "", "none":
		cfg.ClientAuth = dtls.NoClientCert
	case "request":
		cfg.ClientAuth = dtls.RequestClientCert
	case "require_any":
		cfg.ClientAuth = dtls.RequireAnyClientCert
	case "verify_if_given":
		cfg.ClientAuth = dtls.VerifyClientCertIfGiven
	case "require_verify":
		cfg.ClientAuth = dtls.RequireAndVerifyClientCert
	default:
		return nil, fmt.Errorf("dtls: unknown client_auth %q (none, request, require_any, verify_if_given, require_verify)", s.ClientAuth)
	}
	if len(s.ClientCA) > 0 {
		pool := x509.NewCertPool()
		for _, p := range s.ClientCA {
			data, err := os.ReadFile(p)
			if err != nil {
				return nil, fmt.Errorf("dtls: read client_ca: %w", err)
			}
			if !pool.AppendCertsFromPEM(data) {
				return nil, fmt.Errorf("dtls: no certificate in %s", p)
			}
		}
		cfg.ClientCAs = pool
	}
	return cfg, nil
}

type pinnedPacketConn struct {
	net.PacketConn
	peer string
}

func (p *pinnedPacketConn) ReadFrom(b []byte) (int, net.Addr, error) {
	for {
		n, from, err := p.PacketConn.ReadFrom(b)
		if err != nil {
			return n, from, err
		}
		if from.String() == p.peer {
			return n, from, nil
		}
	}
}

type ownedConn struct {
	net.Conn
	extra []io.Closer
	once  sync.Once
}

func (o *ownedConn) Close() error {
	err := o.Conn.Close()
	o.once.Do(func() {
		for _, c := range o.extra {
			c.Close()
		}
	})
	return err
}

func dialDTLS(ctx context.Context, pc net.PacketConn, peer *net.UDPAddr, cfg *dtls.Config, timeout time.Duration, extra ...io.Closer) (net.Conn, error) {
	pp := &pinnedPacketConn{PacketConn: pc, peer: peer.String()}
	fail := func(err error) (net.Conn, error) {
		pc.Close()
		for _, c := range extra {
			c.Close()
		}
		return nil, err
	}
	conn, err := dtls.Client(pp, peer, cfg)
	if err != nil {
		return fail(err)
	}
	hctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	if err := conn.HandshakeContext(hctx); err != nil {
		conn.Close()
		return fail(fmt.Errorf("dtls handshake: %w", err))
	}
	return &ownedConn{Conn: conn, extra: extra}, nil
}

type vconn struct {
	l      *dtlsListener
	remote net.Addr
	key    string
	in     chan []byte
	done   chan struct{}
	once   sync.Once
	dl     *deadline
}

func (v *vconn) ReadFrom(b []byte) (int, net.Addr, error) {
	select {
	case <-v.done:
		return 0, nil, net.ErrClosed
	default:
	}
	select {
	case p := <-v.in:
		return copy(b, p), v.remote, nil
	case <-v.done:
		return 0, nil, net.ErrClosed
	case <-v.dl.wait():
		return 0, nil, timeoutError{}
	}
}

func (v *vconn) WriteTo(b []byte, _ net.Addr) (int, error) {
	select {
	case <-v.done:
		return 0, net.ErrClosed
	default:
	}
	return v.l.sock.WriteTo(b, v.remote)
}

func (v *vconn) Close() error {
	v.once.Do(func() {
		close(v.done)
		v.l.mu.Lock()
		if v.l.m[v.key] == v {
			delete(v.l.m, v.key)
		}
		v.l.mu.Unlock()
	})
	return nil
}

func (v *vconn) LocalAddr() net.Addr                { return v.l.sock.LocalAddr() }
func (v *vconn) SetDeadline(t time.Time) error      { v.dl.set(t); return nil }
func (v *vconn) SetReadDeadline(t time.Time) error  { v.dl.set(t); return nil }
func (v *vconn) SetWriteDeadline(t time.Time) error { return nil }

const (
	maxDTLSSessions = 4096
	maxDTLSPending  = 256
)

type dtlsListener struct {
	sock    net.PacketConn
	cfg     *dtls.Config
	timeout time.Duration
	handle  func(net.Conn)

	mu      sync.Mutex
	m       map[string]*vconn
	pending int
	closed  bool
	wg      sync.WaitGroup
}

func newDTLSListener(sock net.PacketConn, cfg *dtls.Config, timeout time.Duration, handle func(net.Conn)) *dtlsListener {
	l := &dtlsListener{sock: sock, cfg: cfg, timeout: timeout, handle: handle, m: map[string]*vconn{}}
	l.wg.Add(1)
	go l.readLoop()
	return l
}

func (l *dtlsListener) readLoop() {
	defer l.wg.Done()
	buf := make([]byte, 65535)
	for {
		n, from, err := l.sock.ReadFrom(buf)
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(5 * time.Millisecond)
			continue
		}
		key := from.String()
		l.mu.Lock()
		if l.closed {
			l.mu.Unlock()
			return
		}
		v := l.m[key]
		fresh := false
		if v == nil {
			if len(l.m) >= maxDTLSSessions || l.pending >= maxDTLSPending {
				l.mu.Unlock()
				continue
			}
			v = &vconn{l: l, remote: from, key: key, in: make(chan []byte, 128), done: make(chan struct{}), dl: newDeadline()}
			l.m[key] = v
			l.pending++
			fresh = true
		}
		l.mu.Unlock()
		select {
		case v.in <- append([]byte(nil), buf[:n]...):
		default:
		}
		if fresh {
			l.wg.Add(1)
			go l.accept(v)
		}
	}
}

func (l *dtlsListener) accept(v *vconn) {
	defer l.wg.Done()
	settled := false
	settle := func() {
		if !settled {
			settled = true
			l.mu.Lock()
			l.pending--
			l.mu.Unlock()
		}
	}
	defer settle()
	conn, err := dtls.Server(v, v.remote, l.cfg)
	if err != nil {
		v.Close()
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), l.timeout)
	err = conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		conn.Close()
		v.Close()
		return
	}
	settle()
	l.handle(conn)
	conn.Close()
	v.Close()
}

func (l *dtlsListener) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	vs := make([]*vconn, 0, len(l.m))
	for _, v := range l.m {
		vs = append(vs, v)
	}
	l.mu.Unlock()
	l.sock.Close()
	for _, v := range vs {
		v.Close()
	}
	l.wg.Wait()
	return nil
}
