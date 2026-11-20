package vless

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"strings"

	"github.com/n-yarvex/kami-core/addr"
)

const (
	protocolVersion = 0

	cmdTCP = 1
	cmdUDP = 2
	cmdMux = 3

	atypIPv4   = 1
	atypDomain = 2
	atypIPv6   = 3

	muxHost = "v1.mux.cool"
	muxPort = 666

	visionFlow = "xtls-rprx-vision"
)

type UUID [16]byte

func (u UUID) String() string {
	var out [36]byte
	hex.Encode(out[0:8], u[0:4])
	out[8] = '-'
	hex.Encode(out[9:13], u[4:6])
	out[13] = '-'
	hex.Encode(out[14:18], u[6:8])
	out[18] = '-'
	hex.Encode(out[19:23], u[8:10])
	out[23] = '-'
	hex.Encode(out[24:], u[10:])
	return string(out[:])
}

func ParseUUID(s string) (UUID, error) {
	var u UUID
	if s == "" {
		return u, errors.New("empty id")
	}
	if len(s) == 36 && s[8] == '-' && s[13] == '-' && s[18] == '-' && s[23] == '-' {
		raw := strings.ReplaceAll(s, "-", "")
		if b, err := hex.DecodeString(raw); err == nil && len(b) == 16 {
			copy(u[:], b)
			return u, nil
		}
		return u, fmt.Errorf("invalid uuid %q", s)
	}
	if len(s) > 30 {
		return u, fmt.Errorf("id %q is neither a uuid nor a custom string of at most 30 bytes", s)
	}
	h := sha1.New()
	h.Write(make([]byte, 16))
	h.Write([]byte(s))
	sum := h.Sum(nil)
	copy(u[:], sum[:16])
	u[6] = (u[6] & 0x0f) | 0x50
	u[8] = (u[8] & 0x3f) | 0x80
	return u, nil
}

type request struct {
	id   UUID
	cmd  byte
	dest addr.Addr
}

func appendAddr(b []byte, a addr.Addr) ([]byte, error) {
	b = binary.BigEndian.AppendUint16(b, a.Port())
	switch {
	case a.IsIP() && a.IP().Unmap().Is4():
		ip := a.IP().Unmap().As4()
		b = append(b, atypIPv4)
		return append(b, ip[:]...), nil
	case a.IsIP():
		ip := a.IP().As16()
		b = append(b, atypIPv6)
		return append(b, ip[:]...), nil
	case a.IsDomain():
		host := a.Host()
		if len(host) == 0 || len(host) > 255 {
			return nil, errors.New("vless: domain length out of range")
		}
		b = append(b, atypDomain, byte(len(host)))
		return append(b, host...), nil
	}
	return nil, errors.New("vless: invalid address")
}

func readAddr(r io.Reader) (addr.Addr, error) {
	var head [3]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return addr.Addr{}, err
	}
	port := binary.BigEndian.Uint16(head[:2])
	switch head[2] {
	case atypIPv4:
		var ip [4]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return addr.Addr{}, err
		}
		return addr.FromIP(netip.AddrFrom4(ip), port), nil
	case atypIPv6:
		var ip [16]byte
		if _, err := io.ReadFull(r, ip[:]); err != nil {
			return addr.Addr{}, err
		}
		return addr.FromIP(netip.AddrFrom16(ip), port), nil
	case atypDomain:
		var n [1]byte
		if _, err := io.ReadFull(r, n[:]); err != nil {
			return addr.Addr{}, err
		}
		if n[0] == 0 {
			return addr.Addr{}, errors.New("vless: empty domain")
		}
		host := make([]byte, n[0])
		if _, err := io.ReadFull(r, host); err != nil {
			return addr.Addr{}, err
		}
		return addr.FromDomain(string(host), port), nil
	}
	return addr.Addr{}, fmt.Errorf("vless: unknown address type %d", head[2])
}

func appendRequest(b []byte, q request) ([]byte, error) {
	b = append(b, protocolVersion)
	b = append(b, q.id[:]...)
	b = append(b, 0)
	b = append(b, q.cmd)
	if q.cmd == cmdMux {
		return b, nil
	}
	return appendAddr(b, q.dest)
}

func readRequest(r *bufio.Reader) (request, error) {
	var q request
	var head [18]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return q, err
	}
	if head[0] != protocolVersion {
		return q, fmt.Errorf("vless: unsupported version %d", head[0])
	}
	copy(q.id[:], head[1:17])
	if n := int(head[17]); n > 0 {
		addons := make([]byte, n)
		if _, err := io.ReadFull(r, addons); err != nil {
			return q, err
		}
		if bytes.Contains(addons, []byte(visionFlow)) {
			return q, errors.New("vless: flow " + visionFlow + " is not supported")
		}
	}
	cmd, err := r.ReadByte()
	if err != nil {
		return q, err
	}
	q.cmd = cmd
	switch cmd {
	case cmdMux:
		q.dest = addr.FromDomain(muxHost, muxPort)
	case cmdTCP, cmdUDP:
		if q.dest, err = readAddr(r); err != nil {
			return q, err
		}
	default:
		return q, fmt.Errorf("vless: unsupported command %d", cmd)
	}
	return q, nil
}

var responseHeader = []byte{protocolVersion, 0}

func skipResponseHeader(r *bufio.Reader) error {
	head, err := r.Peek(2)
	if err != nil {
		return err
	}
	if head[0] != protocolVersion {
		return fmt.Errorf("vless: unexpected response version %d", head[0])
	}
	if head[1] != 0 {
		n := int(head[1])
		if _, err := r.Discard(2 + n); err != nil {
			return err
		}
		return nil
	}
	_, err = r.Discard(2)
	return err
}
