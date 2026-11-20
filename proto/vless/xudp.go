package vless

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"

	"github.com/n-yarvex/kami-core/addr"
)

const (
	stNew       = 1
	stKeep      = 2
	stEnd       = 3
	stKeepAlive = 4

	optData  = 1
	optError = 2

	netTCP = 1
	netUDP = 2

	maxMeta  = 512
	maxFrame = 65535
)

var errTooLarge = errors.New("xudp: payload too large")

type frame struct {
	id      uint16
	status  byte
	option  byte
	network byte
	dest    addr.Addr
	global  [8]byte
	data    []byte
}

func (f frame) hasData() bool { return f.option&optData != 0 }

func appendFrame(b []byte, f frame) ([]byte, error) {
	if len(f.data) > maxFrame {
		return nil, errTooLarge
	}
	lenAt := len(b)
	b = append(b, 0, 0)
	start := len(b)
	b = binary.BigEndian.AppendUint16(b, f.id)
	b = append(b, f.status, f.option)
	switch {
	case f.status == stNew:
		network := f.network
		if network == 0 {
			network = netUDP
		}
		b = append(b, network)
		var err error
		if b, err = appendAddr(b, f.dest); err != nil {
			return nil, err
		}
		if f.global != [8]byte{} {
			b = append(b, f.global[:]...)
		}
	case f.status == stKeep && f.dest.IsValid():
		b = append(b, netUDP)
		var err error
		if b, err = appendAddr(b, f.dest); err != nil {
			return nil, err
		}
	}
	metaLen := len(b) - start
	if metaLen > maxMeta {
		return nil, errors.New("xudp: metadata too large")
	}
	binary.BigEndian.PutUint16(b[lenAt:], uint16(metaLen))
	if f.hasData() {
		b = binary.BigEndian.AppendUint16(b, uint16(len(f.data)))
		b = append(b, f.data...)
	}
	return b, nil
}

func readFrame(r io.Reader) (frame, error) {
	var f frame
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return f, err
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if n < 4 || n > maxMeta {
		return f, fmt.Errorf("xudp: bad metadata length %d", n)
	}
	meta := make([]byte, n)
	if _, err := io.ReadFull(r, meta); err != nil {
		return f, err
	}
	f.id = binary.BigEndian.Uint16(meta[:2])
	f.status = meta[2]
	f.option = meta[3]
	rest := meta[4:]
	switch f.status {
	case stNew, stKeep, stEnd, stKeepAlive:
	default:
		return f, fmt.Errorf("xudp: unknown status %d", f.status)
	}
	if f.status == stNew || (f.status == stKeep && len(rest) > 0 && rest[0] == netUDP) {
		if len(rest) < 5 {
			return f, errors.New("xudp: short address")
		}
		f.network = rest[0]
		if f.network != netTCP && f.network != netUDP {
			return f, fmt.Errorf("xudp: unknown network %d", f.network)
		}
		br := bytes.NewReader(rest[1:])
		d, err := readAddr(br)
		if err != nil {
			return f, err
		}
		f.dest = d
		rest = rest[1+(len(rest)-1-br.Len()):]
		if f.status == stNew && f.hasData() && f.network == netUDP && len(rest) >= 8 {
			copy(f.global[:], rest[:8])
		}
	}
	if f.hasData() {
		if _, err := io.ReadFull(r, lb[:]); err != nil {
			return f, err
		}
		dl := int(binary.BigEndian.Uint16(lb[:]))
		f.data = make([]byte, dl)
		if _, err := io.ReadFull(r, f.data); err != nil {
			return f, err
		}
	}
	return f, nil
}
