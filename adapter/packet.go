package adapter

import (
	"context"
	"errors"
	"net"
	"time"

	"github.com/n-yarvex/kami-core/addr"
)

var ErrNoUDP = errors.New("udp is not supported here")

type netPacket struct {
	pc  net.PacketConn
	res Resolver
}

func FromNet(pc net.PacketConn, res Resolver) PacketConn {
	return &netPacket{pc: pc, res: res}
}

func (n *netPacket) ReadPacket(p []byte) (int, addr.Addr, error) {
	size, from, err := n.pc.ReadFrom(p)
	if err != nil {
		return 0, addr.Addr{}, err
	}
	return size, addr.FromNet(from), nil
}

func (n *netPacket) WritePacket(p []byte, peer addr.Addr) error {
	if peer.IsDomain() {
		if n.res == nil {
			return errors.New("domain destination without a resolver")
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		ips, err := n.res.Lookup(ctx, peer.Host())
		if err != nil {
			return err
		}
		if len(ips) == 0 {
			return errors.New("no address for " + peer.Host())
		}
		peer = addr.FromIP(ips[0], peer.Port())
	}
	_, err := n.pc.WriteTo(p, peer.UDPAddr())
	return err
}

func (n *netPacket) SetReadDeadline(t time.Time) error { return n.pc.SetReadDeadline(t) }
func (n *netPacket) Close() error                      { return n.pc.Close() }

type packetNet struct {
	pc    PacketConn
	local net.Addr
}

func ToNet(pc PacketConn) net.PacketConn {
	return &packetNet{pc: pc, local: &net.UDPAddr{IP: net.IPv4zero}}
}

func (p *packetNet) ReadFrom(b []byte) (int, net.Addr, error) {
	n, from, err := p.pc.ReadPacket(b)
	if err != nil {
		return 0, nil, err
	}
	if !from.IsIP() {
		return n, &net.UDPAddr{IP: net.IPv4zero, Port: int(from.Port())}, nil
	}
	return n, from.UDPAddr(), nil
}

func (p *packetNet) WriteTo(b []byte, to net.Addr) (int, error) {
	if err := p.pc.WritePacket(b, addr.FromNet(to)); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (p *packetNet) Close() error                      { return p.pc.Close() }
func (p *packetNet) LocalAddr() net.Addr               { return p.local }
func (p *packetNet) SetReadDeadline(t time.Time) error { return p.pc.SetReadDeadline(t) }
func (p *packetNet) SetWriteDeadline(time.Time) error  { return nil }
func (p *packetNet) SetDeadline(t time.Time) error     { return p.pc.SetReadDeadline(t) }
