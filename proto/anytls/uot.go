package anytls

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

const (
	uotHost   = "sp.v2.udp-over-tcp.arpa"
	uotV4     = 0x00
	uotV6     = 0x01
	uotDomain = 0x02
)

var errUoT = errors.New("anytls: bad udp-over-tcp frame")

func appendUoTAddr(dst []byte, a addr.Addr) ([]byte, error) {
	switch {
	case a.IsIP():
		ip := a.IP()
		if ip.Is4() || ip.Is4In6() {
			v := ip.Unmap().As4()
			dst = append(dst, uotV4)
			dst = append(dst, v[:]...)
		} else {
			v := ip.As16()
			dst = append(dst, uotV6)
			dst = append(dst, v[:]...)
		}
	case a.IsDomain():
		h := a.Host()
		if len(h) == 0 || len(h) > 255 {
			return nil, errUoT
		}
		dst = append(dst, uotDomain, byte(len(h)))
		dst = append(dst, h...)
	default:
		return nil, errUoT
	}
	return binary.BigEndian.AppendUint16(dst, a.Port()), nil
}

func readUoTAddr(r *bufio.Reader) (addr.Addr, error) {
	kind, err := r.ReadByte()
	if err != nil {
		return addr.Addr{}, err
	}
	var host addr.Addr
	var port [2]byte
	switch kind {
	case uotV4, uotV6:
		raw := make([]byte, 4)
		if kind == uotV6 {
			raw = make([]byte, 16)
		}
		if _, err := io.ReadFull(r, raw); err != nil {
			return addr.Addr{}, err
		}
		ip, _ := netip.AddrFromSlice(raw)
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return addr.Addr{}, err
		}
		return addr.FromIP(ip, binary.BigEndian.Uint16(port[:])), nil
	case uotDomain:
		n, err := r.ReadByte()
		if err != nil || n == 0 {
			return host, errUoT
		}
		name := make([]byte, n)
		if _, err := io.ReadFull(r, name); err != nil {
			return host, err
		}
		if _, err := io.ReadFull(r, port[:]); err != nil {
			return host, err
		}
		return addr.FromDomain(string(name), binary.BigEndian.Uint16(port[:])), nil
	}
	return host, errUoT
}

type uotConn struct {
	s       *stream
	r       *bufio.Reader
	connect bool
	fixed   addr.Addr

	wmu sync.Mutex
}

func newUoTConn(s *stream, r *bufio.Reader, connect bool, fixed addr.Addr) *uotConn {
	return &uotConn{s: s, r: r, connect: connect, fixed: fixed}
}

func (c *uotConn) ReadPacket(b []byte) (int, addr.Addr, error) {
	peer := c.fixed
	if !c.connect {
		var err error
		if peer, err = readUoTAddr(c.r); err != nil {
			return 0, addr.Addr{}, err
		}
	}
	var size [2]byte
	if _, err := io.ReadFull(c.r, size[:]); err != nil {
		return 0, addr.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > len(b) {
		if _, err := io.CopyN(io.Discard, c.r, int64(n)); err != nil {
			return 0, addr.Addr{}, err
		}
		return 0, peer, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(c.r, b[:n]); err != nil {
		return 0, addr.Addr{}, err
	}
	return n, peer, nil
}

func (c *uotConn) WritePacket(b []byte, peer addr.Addr) error {
	if len(b) > 0xFFFF {
		return errors.New("anytls: datagram too large")
	}
	frame := bufpool.Get(1 + 1 + 255 + 2 + 2 + len(b))
	defer bufpool.Put(frame)
	out := frame[:0]
	if !c.connect {
		var err error
		if out, err = appendUoTAddr(out, peer); err != nil {
			return err
		}
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(b)))
	out = append(out, b...)
	c.wmu.Lock()
	defer c.wmu.Unlock()
	_, err := c.s.Write(out)
	return err
}

func (c *uotConn) SetReadDeadline(t time.Time) error { return c.s.SetReadDeadline(t) }
func (c *uotConn) Close() error                      { return c.s.Close() }

func uotRequest(connect bool, dest addr.Addr) ([]byte, error) {
	target, err := dest.AppendSocks(nil)
	if err != nil {
		return nil, err
	}
	flag := byte(0)
	if connect {
		flag = 1
	}
	return append([]byte{flag}, target...), nil
}
