package juicity

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"

	"github.com/n-yarvex/kami-core/addr"
)

const (
	netTCP byte = 1
	netUDP byte = 3

	atV4     byte = 1
	atV6     byte = 4
	atDomain byte = 3
)

var errHeader = errors.New("juicity: malformed proxy header")

func appendAddr(dst []byte, a addr.Addr) ([]byte, error) {
	switch {
	case a.IsIP():
		ip := a.IP()
		if ip.Is4() || ip.Is4In6() {
			v := ip.Unmap().As4()
			dst = append(dst, atV4)
			dst = append(dst, v[:]...)
		} else {
			v := ip.As16()
			dst = append(dst, atV6)
			dst = append(dst, v[:]...)
		}
	case a.IsDomain():
		h := a.Host()
		if len(h) > 255 {
			return nil, errHeader
		}
		dst = append(dst, atDomain, byte(len(h)))
		dst = append(dst, h...)
	default:
		return nil, errHeader
	}
	return binary.BigEndian.AppendUint16(dst, a.Port()), nil
}

func appendHeader(dst []byte, network byte, a addr.Addr) ([]byte, error) {
	return appendAddr(append(dst, network), a)
}

func readAddr(r *bufio.Reader) (addr.Addr, error) {
	kind, err := r.ReadByte()
	if err != nil {
		return addr.Addr{}, err
	}
	var raw [255]byte
	var n int
	switch kind {
	case atV4:
		n = 4
	case atV6:
		n = 16
	case atDomain:
		l, err := r.ReadByte()
		if err != nil {
			return addr.Addr{}, err
		}
		if l == 0 {
			return addr.Addr{}, errHeader
		}
		n = int(l)
	default:
		return addr.Addr{}, errHeader
	}
	if _, err := io.ReadFull(r, raw[:n]); err != nil {
		return addr.Addr{}, err
	}
	var port [2]byte
	if _, err := io.ReadFull(r, port[:]); err != nil {
		return addr.Addr{}, err
	}
	p := binary.BigEndian.Uint16(port[:])
	if kind == atDomain {
		return addr.FromDomain(string(raw[:n]), p), nil
	}
	ip, _ := netip.AddrFromSlice(raw[:n])
	return addr.FromIP(ip, p), nil
}

func readHeader(r *bufio.Reader) (byte, addr.Addr, error) {
	network, err := r.ReadByte()
	if err != nil {
		return 0, addr.Addr{}, err
	}
	if network != netTCP && network != netUDP {
		return 0, addr.Addr{}, errHeader
	}
	a, err := readAddr(r)
	return network, a, err
}
