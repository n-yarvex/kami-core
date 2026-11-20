package wireguard

import (
	"net"
	"net/netip"
	"sync"

	"golang.zx2c4.com/wireguard/conn"
)

type bind struct {
	mk       func() (net.PacketConn, error)
	reserved *[3]byte

	mu sync.Mutex
	pc net.PacketConn
}

func newBind(mk func() (net.PacketConn, error), reserved *[3]byte) *bind {
	return &bind{mk: mk, reserved: reserved}
}

func (b *bind) Open(uint16) ([]conn.ReceiveFunc, uint16, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.pc != nil {
		return nil, 0, conn.ErrBindAlreadyOpen
	}
	pc, err := b.mk()
	if err != nil {
		return nil, 0, err
	}
	b.pc = pc
	var port uint16
	if ua, ok := pc.LocalAddr().(*net.UDPAddr); ok {
		port = uint16(ua.Port)
	}
	return []conn.ReceiveFunc{func(packets [][]byte, sizes []int, eps []conn.Endpoint) (int, error) {
		for {
			n, from, err := pc.ReadFrom(packets[0])
			if err != nil {
				return 0, err
			}
			ua, ok := from.(*net.UDPAddr)
			if !ok {
				continue
			}
			ap := ua.AddrPort()
			ap = netip.AddrPortFrom(ap.Addr().Unmap(), ap.Port())
			if b.reserved != nil && n >= 4 {
				packets[0][1], packets[0][2], packets[0][3] = 0, 0, 0
			}
			sizes[0] = n
			eps[0] = &conn.StdNetEndpoint{AddrPort: ap}
			return 1, nil
		}
	}}, port, nil
}

func (b *bind) Close() error {
	b.mu.Lock()
	pc := b.pc
	b.pc = nil
	b.mu.Unlock()
	if pc != nil {
		return pc.Close()
	}
	return nil
}

func (b *bind) SetMark(uint32) error { return nil }

func (b *bind) Send(bufs [][]byte, ep conn.Endpoint) error {
	b.mu.Lock()
	pc := b.pc
	b.mu.Unlock()
	if pc == nil {
		return net.ErrClosed
	}
	e, ok := ep.(*conn.StdNetEndpoint)
	if !ok {
		return conn.ErrWrongEndpointType
	}
	to := net.UDPAddrFromAddrPort(e.AddrPort)
	var first error
	for _, p := range bufs {
		if b.reserved != nil && len(p) >= 4 {
			copy(p[1:4], b.reserved[:])
		}
		if _, err := pc.WriteTo(p, to); err != nil && first == nil {
			first = err
		}
	}
	return first
}

func (b *bind) ParseEndpoint(s string) (conn.Endpoint, error) {
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &conn.StdNetEndpoint{AddrPort: ap}, nil
}

func (b *bind) BatchSize() int { return 1 }
