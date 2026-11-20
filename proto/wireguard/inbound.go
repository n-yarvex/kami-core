package wireguard

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.zx2c4.com/wireguard/device"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

type peerOptions struct {
	Name         string   `json:"name"`
	PublicKey    string   `json:"public_key"`
	PresharedKey string   `json:"preshared_key,omitempty"`
	AllowedIPs   []string `json:"allowed_ips"`
	KeepAlive    int      `json:"keepalive,omitempty"`
}

type inboundOptions struct {
	PrivateKey string        `json:"private_key"`
	Peers      []peerOptions `json:"peers"`
	MTU        int           `json:"mtu,omitempty"`
	Reserved   []int         `json:"reserved,omitempty"`
	DisableUDP bool          `json:"disable_udp,omitempty"`
}

type peerEntry struct {
	name     string
	prefixes []netip.Prefix
}

type inbound struct {
	env      *adapter.InboundEnv
	cfg      string
	peers    []peerEntry
	mtu      int
	reserved *[3]byte
	udp      bool

	mu     sync.Mutex
	dev    *device.Device
	closed bool
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("wireguard: %w", err)
	}
	priv, err := hexKey("private_key", o.PrivateKey)
	if err != nil {
		return nil, err
	}
	if len(o.Peers) == 0 {
		return nil, errors.New("wireguard: at least one peer is required")
	}
	mtu, err := checkMTU(o.MTU)
	if err != nil {
		return nil, err
	}
	reserved, err := checkReserved(o.Reserved)
	if err != nil {
		return nil, err
	}
	in := &inbound{env: env, mtu: mtu, reserved: reserved, udp: !o.DisableUDP}
	var b strings.Builder
	fmt.Fprintf(&b, "private_key=%s\n", priv)
	seenKeys := map[string]bool{}
	seenNames := map[string]bool{}
	for i, p := range o.Peers {
		pub, err := hexKey(fmt.Sprintf("peers[%d].public_key", i), p.PublicKey)
		if err != nil {
			return nil, err
		}
		if seenKeys[pub] {
			return nil, fmt.Errorf("wireguard: peers[%d] repeats a public key", i)
		}
		seenKeys[pub] = true
		name := p.Name
		if name == "" {
			name = fmt.Sprintf("peer%d", i+1)
		}
		if seenNames[name] {
			return nil, fmt.Errorf("wireguard: peer name %q is used twice", name)
		}
		seenNames[name] = true
		if len(p.AllowedIPs) == 0 {
			return nil, fmt.Errorf("wireguard: peers[%d].allowed_ips is required", i)
		}
		prefixes, err := parsePrefixes("allowed_ips", p.AllowedIPs)
		if err != nil {
			return nil, err
		}
		fmt.Fprintf(&b, "public_key=%s\n", pub)
		if p.PresharedKey != "" {
			psk, err := hexKey(fmt.Sprintf("peers[%d].preshared_key", i), p.PresharedKey)
			if err != nil {
				return nil, err
			}
			fmt.Fprintf(&b, "preshared_key=%s\n", psk)
		}
		if p.KeepAlive > 0 {
			fmt.Fprintf(&b, "persistent_keepalive_interval=%d\n", p.KeepAlive)
		}
		for _, pf := range prefixes {
			fmt.Fprintf(&b, "allowed_ip=%s\n", pf)
		}
		in.peers = append(in.peers, peerEntry{name: name, prefixes: prefixes})
	}
	in.cfg = b.String()
	return in, nil
}

func (in *inbound) Tag() string  { return in.env.Tag }
func (in *inbound) Type() string { return "wireguard" }

func (in *inbound) userOf(ip netip.Addr) string {
	ip = ip.Unmap()
	for _, p := range in.peers {
		for _, pf := range p.prefixes {
			if pf.Contains(ip) {
				return p.name
			}
		}
	}
	return ""
}

func fromTCPIP(a tcpip.Address, port uint16) addr.Addr {
	ip, _ := netip.AddrFromSlice(a.AsSlice())
	return addr.FromIP(ip.Unmap(), port)
}

func (in *inbound) Start() error {
	ts, err := newTunStack(in.mtu, nil, true)
	if err != nil {
		return err
	}
	tcpFwd := tcp.NewForwarder(ts.st, 0, 2048, func(r *tcp.ForwarderRequest) {
		id := r.ID()
		var wq waiter.Queue
		ep, terr := r.CreateEndpoint(&wq)
		if terr != nil {
			r.Complete(true)
			return
		}
		r.Complete(false)
		conn := gonet.NewTCPConn(&wq, ep)
		src := fromTCPIP(id.RemoteAddress, id.RemotePort)
		dst := fromTCPIP(id.LocalAddress, id.LocalPort)
		in.wg.Add(1)
		go func() {
			defer in.wg.Done()
			in.env.Router.Stream(in.env.Ctx, conn, adapter.Metadata{
				Inbound:     in.env.Tag,
				InboundType: "wireguard",
				User:        in.userOf(src.IP()),
				Network:     "tcp",
				Source:      src,
				Dest:        dst,
			})
			conn.Close()
		}()
	})
	ts.st.SetTransportProtocolHandler(tcp.ProtocolNumber, tcpFwd.HandlePacket)
	if in.udp {
		udpFwd := udp.NewForwarder(ts.st, func(r *udp.ForwarderRequest) {
			id := r.ID()
			var wq waiter.Queue
			ep, terr := r.CreateEndpoint(&wq)
			if terr != nil {
				return
			}
			conn := gonet.NewUDPConn(&wq, ep)
			src := fromTCPIP(id.RemoteAddress, id.RemotePort)
			dst := fromTCPIP(id.LocalAddress, id.LocalPort)
			pc := &fwdUDP{conn: conn, dest: dst}
			in.wg.Add(1)
			go func() {
				defer in.wg.Done()
				in.env.Router.Packet(in.env.Ctx, pc, adapter.Metadata{
					Inbound:     in.env.Tag,
					InboundType: "wireguard",
					User:        in.userOf(src.IP()),
					Network:     "udp",
					Source:      src,
					Dest:        dst,
				})
				pc.Close()
			}()
		})
		ts.st.SetTransportProtocolHandler(udp.ProtocolNumber, udpFwd.HandlePacket)
	}
	sock, err := in.env.ListenUDP()
	if err != nil {
		ts.Close()
		return err
	}
	used := false
	mk := func() (net.PacketConn, error) {
		if used {
			return nil, errors.New("wireguard: listening socket cannot be reopened")
		}
		used = true
		return sock, nil
	}
	dev := device.NewDevice(ts, newBind(mk, in.reserved), deviceLogger(in.env.Log, in.env.Tag))
	if err := dev.IpcSet(in.cfg); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: configure: %w", err)
	}
	if err := dev.Up(); err != nil {
		dev.Close()
		return fmt.Errorf("wireguard: up: %w", err)
	}
	in.mu.Lock()
	in.dev = dev
	in.mu.Unlock()
	return nil
}

func (in *inbound) Close() error {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return nil
	}
	in.closed = true
	dev := in.dev
	in.mu.Unlock()
	if dev != nil {
		dev.Close()
	}
	in.wg.Wait()
	return nil
}

type fwdUDP struct {
	conn *gonet.UDPConn
	dest addr.Addr
}

func (f *fwdUDP) ReadPacket(b []byte) (int, addr.Addr, error) {
	buf := bufpool.Get(65535)
	defer bufpool.Put(buf)
	n, err := f.conn.Read(buf)
	if err != nil {
		return 0, addr.Addr{}, err
	}
	return copy(b, buf[:n]), f.dest, nil
}

func (f *fwdUDP) WritePacket(b []byte, _ addr.Addr) error {
	_, err := f.conn.Write(b)
	return err
}

func (f *fwdUDP) SetReadDeadline(t time.Time) error { return f.conn.SetReadDeadline(t) }
func (f *fwdUDP) Close() error                      { return f.conn.Close() }
