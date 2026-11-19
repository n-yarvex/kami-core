package addr

import (
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

const (
	atypIPv4   = 1
	atypDomain = 3
	atypIPv6   = 4
)

var (
	ErrBadAddr = errors.New("addr: malformed address")
	ErrShort   = errors.New("addr: buffer too short")
)

type Addr struct {
	host string
	ip   netip.Addr
	port uint16
}

func FromIP(ip netip.Addr, port uint16) Addr {
	return Addr{ip: ip.Unmap(), port: port}
}

func FromAddrPort(ap netip.AddrPort) Addr {
	return FromIP(ap.Addr(), ap.Port())
}

func FromDomain(host string, port uint16) Addr {
	return Addr{host: host, port: port}
}

func FromHost(host string, port uint16) Addr {
	if i := strings.IndexByte(host, '%'); i > 0 {
		host = host[:i]
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return FromIP(ip, port)
	}
	return FromDomain(strings.TrimSuffix(host, "."), port)
}

func Parse(s string) (Addr, error) {
	host, p, err := net.SplitHostPort(s)
	if err != nil {
		return Addr{}, err
	}
	port, err := strconv.ParseUint(p, 10, 16)
	if err != nil {
		return Addr{}, ErrBadAddr
	}
	a := FromHost(host, uint16(port))
	if !a.IsValid() {
		return Addr{}, ErrBadAddr
	}
	return a, nil
}

func FromNet(n net.Addr) Addr {
	switch v := n.(type) {
	case *net.UDPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return FromIP(ip, uint16(v.Port))
		}
	case *net.TCPAddr:
		if ip, ok := netip.AddrFromSlice(v.IP); ok {
			return FromIP(ip, uint16(v.Port))
		}
	case nil:
		return Addr{}
	}
	a, _ := Parse(n.String())
	return a
}

func (a Addr) IsIP() bool     { return a.ip.IsValid() }
func (a Addr) IsDomain() bool { return !a.ip.IsValid() && a.host != "" }
func (a Addr) IsValid() bool  { return a.IsIP() || a.IsDomain() }
func (a Addr) IP() netip.Addr { return a.ip }
func (a Addr) Port() uint16   { return a.port }

func (a Addr) Host() string {
	if a.ip.IsValid() {
		return a.ip.String()
	}
	return a.host
}

func (a Addr) String() string {
	if !a.IsValid() {
		return ""
	}
	return net.JoinHostPort(a.Host(), strconv.Itoa(int(a.port)))
}

func (a Addr) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(a.ip, a.port)
}

func (a Addr) UDPAddr() *net.UDPAddr {
	if !a.ip.IsValid() {
		return nil
	}
	return net.UDPAddrFromAddrPort(a.AddrPort())
}

func (a Addr) TCPAddr() *net.TCPAddr {
	if !a.ip.IsValid() {
		return nil
	}
	return net.TCPAddrFromAddrPort(a.AddrPort())
}

func (a Addr) WithPort(port uint16) Addr {
	a.port = port
	return a
}

func (a Addr) SocksLen() int {
	switch {
	case a.ip.Is4():
		return 1 + 4 + 2
	case a.ip.IsValid():
		return 1 + 16 + 2
	default:
		return 1 + 1 + len(a.host) + 2
	}
}

func (a Addr) AppendSocks(b []byte) ([]byte, error) {
	switch {
	case a.ip.Is4():
		b = append(b, atypIPv4)
		v := a.ip.As4()
		b = append(b, v[:]...)
	case a.ip.IsValid():
		b = append(b, atypIPv6)
		v := a.ip.As16()
		b = append(b, v[:]...)
	case a.host != "" && len(a.host) <= 255:
		b = append(b, atypDomain, byte(len(a.host)))
		b = append(b, a.host...)
	default:
		return b, ErrBadAddr
	}
	return append(b, byte(a.port>>8), byte(a.port)), nil
}

func ParseSocks(b []byte) (Addr, int, error) {
	if len(b) < 1 {
		return Addr{}, 0, ErrShort
	}
	var host Addr
	var n int
	switch b[0] {
	case atypIPv4:
		n = 1 + 4
		if len(b) < n+2 {
			return Addr{}, 0, ErrShort
		}
		host = FromIP(netip.AddrFrom4([4]byte(b[1:5])), 0)
	case atypIPv6:
		n = 1 + 16
		if len(b) < n+2 {
			return Addr{}, 0, ErrShort
		}
		host = FromIP(netip.AddrFrom16([16]byte(b[1:17])), 0)
	case atypDomain:
		if len(b) < 2 {
			return Addr{}, 0, ErrShort
		}
		l := int(b[1])
		n = 2 + l
		if l == 0 {
			return Addr{}, 0, ErrBadAddr
		}
		if len(b) < n+2 {
			return Addr{}, 0, ErrShort
		}
		host = FromHost(string(b[2:n]), 0)
	default:
		return Addr{}, 0, ErrBadAddr
	}
	host.port = uint16(b[n])<<8 | uint16(b[n+1])
	return host, n + 2, nil
}

func ReadSocks(r io.Reader) (Addr, error) {
	var head [2]byte
	if _, err := io.ReadFull(r, head[:1]); err != nil {
		return Addr{}, err
	}
	var buf []byte
	switch head[0] {
	case atypIPv4:
		buf = make([]byte, 1+4+2)
	case atypIPv6:
		buf = make([]byte, 1+16+2)
	case atypDomain:
		if _, err := io.ReadFull(r, head[1:2]); err != nil {
			return Addr{}, err
		}
		buf = make([]byte, 2+int(head[1])+2)
		buf[1] = head[1]
	default:
		return Addr{}, ErrBadAddr
	}
	buf[0] = head[0]
	skip := 1
	if head[0] == atypDomain {
		skip = 2
	}
	if _, err := io.ReadFull(r, buf[skip:]); err != nil {
		return Addr{}, err
	}
	a, _, err := ParseSocks(buf)
	return a, err
}
