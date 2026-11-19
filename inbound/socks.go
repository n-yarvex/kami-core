package inbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
	"github.com/n-yarvex/kami-core/outbound"
)

const (
	socksVersion = 5
	cmdConnect   = 1
	cmdAssociate = 3

	repOK          = 0
	repFailure     = 1
	repNotAllowed  = 2
	repNetUnreach  = 3
	repHostUnreach = 4
	repRefused     = 5
	repCmdUnsup    = 7
	repAtypUnsup   = 8
)

func init() {
	adapter.RegisterInbound("socks", func(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
		return newSocks(env, "socks", raw)
	})
}

type socksOptions struct {
	Users []User `json:"users"`
	UDP   *bool  `json:"udp"`
}

type socksInbound struct {
	base
	users users
	udp   bool
}

func newSocks(env *adapter.InboundEnv, typ string, raw json.RawMessage) (*socksInbound, error) {
	var o socksOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	u, err := newUsers(o.Users)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", typ, err)
	}
	return &socksInbound{base: base{env: env, typ: typ}, users: u, udp: o.UDP == nil || *o.UDP}, nil
}

func (s *socksInbound) Start() error {
	return s.serve(func(conn net.Conn) {
		defer conn.Close()
		s.handle(wrap(conn))
	})
}

func reply(conn net.Conn, code byte, bound addr.Addr) error {
	out := []byte{socksVersion, code, 0}
	if !bound.IsValid() {
		bound = addr.FromIP(netip.IPv4Unspecified(), 0)
	}
	out, err := bound.AppendSocks(out)
	if err != nil {
		return err
	}
	_, err = conn.Write(out)
	return err
}

func (s *socksInbound) negotiate(c *buffered) (user string, err error) {
	var head [2]byte
	if _, err = io.ReadFull(c, head[:]); err != nil {
		return
	}
	if head[0] != socksVersion {
		return "", errors.New("not a socks5 client")
	}
	methods := make([]byte, head[1])
	if _, err = io.ReadFull(c, methods); err != nil {
		return
	}
	offered := func(m byte) bool {
		for _, x := range methods {
			if x == m {
				return true
			}
		}
		return false
	}
	if s.users == nil {
		if !offered(0) {
			c.Write([]byte{socksVersion, 0xff})
			return "", errors.New("client offers no acceptable auth method")
		}
		_, err = c.Write([]byte{socksVersion, 0})
		return "", err
	}
	if !offered(2) {
		c.Write([]byte{socksVersion, 0xff})
		return "", errors.New("client does not offer password auth")
	}
	if _, err = c.Write([]byte{socksVersion, 2}); err != nil {
		return
	}
	var ver [2]byte
	if _, err = io.ReadFull(c, ver[:1]); err != nil || ver[0] != 1 {
		return "", errors.New("bad auth version")
	}
	if _, err = io.ReadFull(c, ver[1:2]); err != nil {
		return
	}
	name := make([]byte, ver[1])
	if _, err = io.ReadFull(c, name); err != nil {
		return
	}
	var plen [1]byte
	if _, err = io.ReadFull(c, plen[:]); err != nil {
		return
	}
	pass := make([]byte, plen[0])
	if _, err = io.ReadFull(c, pass); err != nil {
		return
	}
	if !s.users.check(string(name), string(pass)) {
		c.Write([]byte{1, 1})
		return "", errors.New("bad credentials")
	}
	_, err = c.Write([]byte{1, 0})
	return string(name), err
}

func (s *socksInbound) handle(c *buffered) {
	c.SetDeadline(time.Now().Add(handshakeTimeout))
	user, err := s.negotiate(c)
	if err != nil {
		s.env.Log.Debug("socks handshake failed", "from", c.RemoteAddr().String(), "err", err)
		return
	}
	var req [3]byte
	if _, err := io.ReadFull(c, req[:]); err != nil || req[0] != socksVersion {
		return
	}
	dest, err := addr.ReadSocks(c)
	if err != nil {
		reply(c, repAtypUnsup, addr.Addr{})
		return
	}
	switch req[1] {
	case cmdConnect:
		s.connect(c, user, dest)
	case cmdAssociate:
		if !s.udp {
			reply(c, repCmdUnsup, addr.Addr{})
			return
		}
		s.associate(c, user)
	default:
		reply(c, repCmdUnsup, addr.Addr{})
	}
}

func replyFor(err error) byte {
	switch {
	case err == nil:
		return repOK
	case errors.Is(err, outbound.ErrForbidden):
		return repNotAllowed
	}
	msg := err.Error()
	switch {
	case strings.Contains(msg, "refused"):
		return repRefused
	case strings.Contains(msg, "network is unreachable"):
		return repNetUnreach
	case strings.Contains(msg, "no route"), strings.Contains(msg, "no such host"), strings.Contains(msg, "no address"):
		return repHostUnreach
	}
	return repFailure
}

func (s *socksInbound) connect(c *buffered, user string, dest addr.Addr) {
	m := md(s.env, s.typ, "tcp", user, c, dest)
	var once sync.Once
	m.OnConnect = func(err error) {
		once.Do(func() {
			code := replyFor(err)
			if code == repOK {
				c.SetDeadline(time.Time{})
			}
			reply(c, code, addr.Addr{})
		})
	}
	s.env.Router.Stream(s.env.Ctx, c.handoff(), m)
}

type socksPacket struct {
	relay  net.PacketConn
	peerIP netip.Addr
	mu     sync.Mutex
	client *net.UDPAddr
	buf    []byte
}

func (p *socksPacket) ReadPacket(b []byte) (int, addr.Addr, error) {
	for {
		n, from, err := p.relay.ReadFrom(p.buf)
		if err != nil {
			return 0, addr.Addr{}, err
		}
		ua := from.(*net.UDPAddr)
		ip, _ := netip.AddrFromSlice(ua.IP)
		p.mu.Lock()
		known := p.client
		p.mu.Unlock()
		if known == nil && ip.Unmap() != p.peerIP {
			continue
		}
		if known != nil && (!ua.IP.Equal(known.IP) || ua.Port != known.Port) {
			continue
		}
		pkt := p.buf[:n]
		if len(pkt) < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
			continue
		}
		dest, used, err := addr.ParseSocks(pkt[3:])
		if err != nil {
			continue
		}
		if known == nil {
			p.mu.Lock()
			p.client = ua
			p.mu.Unlock()
		}
		return copy(b, pkt[3+used:]), dest, nil
	}
}

func (p *socksPacket) WritePacket(b []byte, peer addr.Addr) error {
	p.mu.Lock()
	client := p.client
	p.mu.Unlock()
	if client == nil {
		return errors.New("socks udp: client address not learned yet")
	}
	out := bufpool.Get(3 + peer.SocksLen() + len(b))
	defer bufpool.Put(out)
	out[0], out[1], out[2] = 0, 0, 0
	hdr, err := peer.AppendSocks(out[3:3])
	if err != nil {
		return err
	}
	copy(out[3+len(hdr):], b)
	_, err = p.relay.WriteTo(out[:3+len(hdr)+len(b)], client)
	return err
}

func (p *socksPacket) SetReadDeadline(t time.Time) error { return p.relay.SetReadDeadline(t) }

func (p *socksPacket) Close() error {
	bufpool.Put(p.buf)
	return p.relay.Close()
}

func (s *socksInbound) associate(c *buffered, user string) {
	local := c.LocalAddr().(*net.TCPAddr)
	relay, err := net.ListenPacket("udp", net.JoinHostPort(local.IP.String(), "0"))
	if err != nil {
		reply(c, repFailure, addr.Addr{})
		return
	}
	peer, _ := netip.AddrFromSlice(c.RemoteAddr().(*net.TCPAddr).IP)
	pc := &socksPacket{relay: relay, peerIP: peer.Unmap(), buf: bufpool.Get(65535)}
	if err := reply(c, repOK, addr.FromNet(relay.LocalAddr())); err != nil {
		pc.Close()
		return
	}
	c.SetDeadline(time.Time{})
	m := md(s.env, s.typ, "udp", user, c, addr.Addr{})
	ctx, cancel := context.WithCancel(s.env.Ctx)
	defer cancel()
	done := make(chan struct{})
	go func() {
		defer close(done)
		s.env.Router.Packet(ctx, pc, m)
	}()
	go func() {
		io.Copy(io.Discard, c)
		cancel()
		relay.Close()
	}()
	<-done
	c.Close()
}
