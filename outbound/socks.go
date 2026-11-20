package outbound

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

const (
	socks5          = 5
	socksCmdConnect = 1
	socksCmdUDP     = 3
	socksStepLimit  = 15 * time.Second
)

func init() {
	adapter.RegisterOutbound("socks", newSocksOutbound)
}

type socksOutboundOptions struct {
	Server   string `json:"server"`
	Username string `json:"username"`
	Password string `json:"password"`
	UDP      *bool  `json:"udp"`
}

type socksOutbound struct {
	env      *adapter.OutboundEnv
	server   addr.Addr
	username string
	password string
	udp      bool
}

func newSocksOutbound(env *adapter.OutboundEnv, raw json.RawMessage) (adapter.Outbound, error) {
	var o socksOutboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("socks: %w", err)
	}
	server, err := addr.Parse(o.Server)
	if err != nil || server.Port() == 0 {
		return nil, fmt.Errorf("socks: bad server %q (want host:port)", o.Server)
	}
	if (o.Username == "") != (o.Password == "") {
		return nil, errors.New("socks: username and password must be given together")
	}
	if len(o.Username) > 255 || len(o.Password) > 255 {
		return nil, errors.New("socks: username and password must be at most 255 bytes")
	}
	return &socksOutbound{
		env:      env,
		server:   server,
		username: o.Username,
		password: o.Password,
		udp:      o.UDP == nil || *o.UDP,
	}, nil
}

func (s *socksOutbound) Tag() string       { return s.env.Tag }
func (s *socksOutbound) Type() string      { return "socks" }
func (s *socksOutbound) SupportsUDP() bool { return s.udp }
func (s *socksOutbound) Close() error      { return nil }

func (s *socksOutbound) open(ctx context.Context, cmd byte, dest addr.Addr) (net.Conn, addr.Addr, error) {
	conn, err := s.env.Dialer.DialStream(ctx, s.server)
	if err != nil {
		return nil, addr.Addr{}, err
	}
	limit := time.Now().Add(socksStepLimit)
	if dl, ok := ctx.Deadline(); ok && dl.Before(limit) {
		limit = dl
	}
	conn.SetDeadline(limit)
	stop := context.AfterFunc(ctx, func() { conn.SetDeadline(time.Now()) })
	defer stop()
	bound, err := s.handshake(conn, cmd, dest)
	if err != nil {
		conn.Close()
		if ctx.Err() != nil {
			return nil, addr.Addr{}, ctx.Err()
		}
		return nil, addr.Addr{}, err
	}
	conn.SetDeadline(time.Time{})
	return conn, bound, nil
}

func (s *socksOutbound) handshake(conn net.Conn, cmd byte, dest addr.Addr) (addr.Addr, error) {
	offer := []byte{socks5, 1, 0}
	if s.username != "" {
		offer = []byte{socks5, 2, 0, 2}
	}
	if _, err := conn.Write(offer); err != nil {
		return addr.Addr{}, err
	}
	var choice [2]byte
	if _, err := io.ReadFull(conn, choice[:]); err != nil {
		return addr.Addr{}, fmt.Errorf("socks: read method: %w", err)
	}
	if choice[0] != socks5 {
		return addr.Addr{}, errors.New("socks: server is not a socks5 proxy")
	}
	switch choice[1] {
	case 0:
	case 2:
		if s.username == "" {
			return addr.Addr{}, errors.New("socks: server demands authentication but no credentials are configured")
		}
		msg := make([]byte, 0, 3+len(s.username)+len(s.password))
		msg = append(msg, 1, byte(len(s.username)))
		msg = append(msg, s.username...)
		msg = append(msg, byte(len(s.password)))
		msg = append(msg, s.password...)
		if _, err := conn.Write(msg); err != nil {
			return addr.Addr{}, err
		}
		var verdict [2]byte
		if _, err := io.ReadFull(conn, verdict[:]); err != nil {
			return addr.Addr{}, fmt.Errorf("socks: read auth reply: %w", err)
		}
		if verdict[1] != 0 {
			return addr.Addr{}, errors.New("socks: authentication rejected")
		}
	default:
		return addr.Addr{}, errors.New("socks: server accepts none of the offered auth methods")
	}
	req, err := dest.AppendSocks([]byte{socks5, cmd, 0})
	if err != nil {
		return addr.Addr{}, err
	}
	if _, err := conn.Write(req); err != nil {
		return addr.Addr{}, err
	}
	var head [3]byte
	if _, err := io.ReadFull(conn, head[:]); err != nil {
		return addr.Addr{}, fmt.Errorf("socks: read reply: %w", err)
	}
	if head[0] != socks5 {
		return addr.Addr{}, errors.New("socks: bad reply version")
	}
	bound, err := addr.ReadSocks(conn)
	if err != nil {
		return addr.Addr{}, fmt.Errorf("socks: read bound address: %w", err)
	}
	if head[1] != 0 {
		return addr.Addr{}, socksError(head[1])
	}
	return bound, nil
}

func socksError(code byte) error {
	switch code {
	case 1:
		return errors.New("socks: general failure")
	case 2:
		return fmt.Errorf("socks: connection not allowed by ruleset: %w", ErrForbidden)
	case 3:
		return errors.New("socks: network is unreachable")
	case 4:
		return errors.New("socks: no route to host")
	case 5:
		return errors.New("socks: connection refused")
	case 6:
		return errors.New("socks: ttl expired")
	case 7:
		return errors.New("socks: command not supported")
	case 8:
		return errors.New("socks: address type not supported")
	}
	return fmt.Errorf("socks: reply code %d", code)
}

func (s *socksOutbound) DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error) {
	conn, _, err := s.open(ctx, socksCmdConnect, dest)
	return conn, err
}

func (s *socksOutbound) OpenPacket(ctx context.Context, _ addr.Addr) (adapter.PacketConn, error) {
	if !s.udp {
		return nil, adapter.ErrNoUDP
	}
	ctrl, bound, err := s.open(ctx, socksCmdUDP, addr.FromIP(netip.IPv4Unspecified(), 0))
	if err != nil {
		return nil, err
	}
	relay := bound
	if relay.IsIP() && relay.IP().IsUnspecified() {
		relay = addr.FromHost(s.server.Host(), bound.Port())
	}
	if relay.IsDomain() {
		ips, err := s.env.Resolver.Lookup(ctx, relay.Host())
		if err != nil || len(ips) == 0 {
			ctrl.Close()
			return nil, fmt.Errorf("socks: resolve udp relay %s: %w", relay.Host(), err)
		}
		relay = addr.FromIP(ips[0], relay.Port())
	}
	sock, err := s.env.Dialer.ListenPacket(ctx)
	if err != nil {
		ctrl.Close()
		return nil, err
	}
	pc := &socksUDP{ctrl: ctrl, sock: sock, relay: relay.UDPAddr()}
	go pc.watch()
	return pc, nil
}

type socksUDP struct {
	ctrl  net.Conn
	sock  net.PacketConn
	relay *net.UDPAddr
	once  sync.Once
}

func (p *socksUDP) watch() {
	io.Copy(io.Discard, p.ctrl)
	p.Close()
}

func (p *socksUDP) ReadPacket(b []byte) (int, addr.Addr, error) {
	buf := bufpool.Get(65535)
	defer bufpool.Put(buf)
	for {
		n, from, err := p.sock.ReadFrom(buf)
		if err != nil {
			return 0, addr.Addr{}, err
		}
		ua, ok := from.(*net.UDPAddr)
		if !ok || !ua.IP.Equal(p.relay.IP) || ua.Port != p.relay.Port {
			continue
		}
		pkt := buf[:n]
		if len(pkt) < 4 || pkt[0] != 0 || pkt[1] != 0 || pkt[2] != 0 {
			continue
		}
		src, used, err := addr.ParseSocks(pkt[3:])
		if err != nil {
			continue
		}
		return copy(b, pkt[3+used:]), src, nil
	}
}

func (p *socksUDP) WritePacket(b []byte, peer addr.Addr) error {
	out := bufpool.Get(3 + peer.SocksLen() + len(b))
	defer bufpool.Put(out)
	out[0], out[1], out[2] = 0, 0, 0
	hdr, err := peer.AppendSocks(out[3:3])
	if err != nil {
		return err
	}
	copy(out[3+len(hdr):], b)
	_, err = p.sock.WriteTo(out[:3+len(hdr)+len(b)], p.relay)
	return err
}

func (p *socksUDP) SetReadDeadline(t time.Time) error { return p.sock.SetReadDeadline(t) }

func (p *socksUDP) Close() error {
	p.once.Do(func() {
		p.ctrl.Close()
		p.sock.Close()
	})
	return nil
}
