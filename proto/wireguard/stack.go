package wireguard

import (
	"errors"
	"fmt"
	"net/netip"
	"os"
	"sync"
	"syscall"

	"golang.zx2c4.com/wireguard/tun"
	"gvisor.dev/gvisor/pkg/buffer"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/link/channel"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv6"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/icmp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

const nicID = 1

type tunStack struct {
	ep     *channel.Endpoint
	st     *stack.Stack
	events chan tun.Event
	out    chan *buffer.View
	handle *channel.NotificationHandle
	mtu    int
	done   chan struct{}
	once   sync.Once
}

func newTunStack(mtu int, addrs []netip.Prefix, promiscuous bool) (*tunStack, error) {
	st := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol, ipv6.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol, udp.NewProtocol, icmp.NewProtocol4, icmp.NewProtocol6},
		HandleLocal:        !promiscuous,
	})
	t := &tunStack{
		ep:     channel.New(1024, uint32(mtu), ""),
		st:     st,
		events: make(chan tun.Event, 4),
		out:    make(chan *buffer.View, 1024),
		mtu:    mtu,
		done:   make(chan struct{}),
	}
	sack := tcpip.TCPSACKEnabled(true)
	if err := st.SetTransportProtocolOption(tcp.ProtocolNumber, &sack); err != nil {
		return nil, fmt.Errorf("enable tcp sack: %v", err)
	}
	t.handle = t.ep.AddNotify(t)
	if err := st.CreateNIC(nicID, t.ep); err != nil {
		return nil, fmt.Errorf("create nic: %v", err)
	}
	var v4, v6 bool
	for _, p := range addrs {
		proto := ipv4.ProtocolNumber
		if p.Addr().Is6() {
			proto = ipv6.ProtocolNumber
			v6 = true
		} else {
			v4 = true
		}
		pa := tcpip.ProtocolAddress{
			Protocol:          proto,
			AddressWithPrefix: tcpip.AddrFromSlice(p.Addr().AsSlice()).WithPrefix(),
		}
		pa.AddressWithPrefix.PrefixLen = p.Bits()
		if err := st.AddProtocolAddress(nicID, pa, stack.AddressProperties{}); err != nil {
			return nil, fmt.Errorf("add address %s: %v", p, err)
		}
	}
	if promiscuous {
		v4, v6 = true, true
		if err := st.SetPromiscuousMode(nicID, true); err != nil {
			return nil, fmt.Errorf("promiscuous mode: %v", err)
		}
		if err := st.SetSpoofing(nicID, true); err != nil {
			return nil, fmt.Errorf("spoofing: %v", err)
		}
	}
	if v4 {
		st.AddRoute(tcpip.Route{Destination: header.IPv4EmptySubnet, NIC: nicID})
	}
	if v6 {
		st.AddRoute(tcpip.Route{Destination: header.IPv6EmptySubnet, NIC: nicID})
	}
	t.events <- tun.EventUp
	return t, nil
}

func (t *tunStack) WriteNotify() {
	for {
		pkt := t.ep.Read()
		if pkt == nil {
			return
		}
		view := pkt.ToView()
		pkt.DecRef()
		select {
		case t.out <- view:
		case <-t.done:
			return
		default:
		}
	}
}

func (t *tunStack) File() *os.File           { return nil }
func (t *tunStack) Name() (string, error)    { return "kami", nil }
func (t *tunStack) MTU() (int, error)        { return t.mtu, nil }
func (t *tunStack) BatchSize() int           { return 1 }
func (t *tunStack) Events() <-chan tun.Event { return t.events }

func (t *tunStack) Read(bufs [][]byte, sizes []int, offset int) (int, error) {
	select {
	case view := <-t.out:
		n, err := view.Read(bufs[0][offset:])
		view.Release()
		if err != nil {
			return 0, err
		}
		sizes[0] = n
		return 1, nil
	case <-t.done:
		return 0, os.ErrClosed
	}
}

func (t *tunStack) Write(bufs [][]byte, offset int) (int, error) {
	select {
	case <-t.done:
		return 0, os.ErrClosed
	default:
	}
	for _, b := range bufs {
		p := b[offset:]
		if len(p) == 0 {
			continue
		}
		pkb := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(p)})
		switch p[0] >> 4 {
		case 4:
			t.ep.InjectInbound(header.IPv4ProtocolNumber, pkb)
		case 6:
			t.ep.InjectInbound(header.IPv6ProtocolNumber, pkb)
		default:
			pkb.DecRef()
			return 0, syscall.EAFNOSUPPORT
		}
		pkb.DecRef()
	}
	return len(bufs), nil
}

func (t *tunStack) Close() error {
	t.once.Do(func() {
		close(t.done)
		t.st.RemoveNIC(nicID)
		t.st.Close()
		t.ep.RemoveNotify(t.handle)
		t.ep.Close()
		close(t.events)
	})
	return nil
}

var errNoFamily = errors.New("wireguard: no local address for this address family")

func protoOf(a netip.Addr) tcpip.NetworkProtocolNumber {
	if a.Is4() {
		return ipv4.ProtocolNumber
	}
	return ipv6.ProtocolNumber
}

func fullAddr(a netip.Addr, port uint16) tcpip.FullAddress {
	return tcpip.FullAddress{NIC: nicID, Addr: tcpip.AddrFromSlice(a.AsSlice()), Port: port}
}
