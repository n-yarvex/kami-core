package juicity

import (
	"bufio"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

type datagramConn struct {
	s      *quic.Stream
	r      *bufio.Reader
	client bool
	idle   *idler

	wmu   sync.Mutex
	begun bool
	once  sync.Once
}

func newDatagramConn(s *quic.Stream, r *bufio.Reader, client bool, nat time.Duration) *datagramConn {
	d := &datagramConn{s: s, r: r, client: client}
	if r == nil {
		d.r = bufio.NewReaderSize(s, 4096)
	}
	d.idle = newIdler(nat, func() { d.Close() })
	return d
}

func (d *datagramConn) ReadPacket(b []byte) (int, addr.Addr, error) {
	peer, err := readAddr(d.r)
	if err != nil {
		return 0, addr.Addr{}, err
	}
	var size [2]byte
	if _, err := io.ReadFull(d.r, size[:]); err != nil {
		return 0, addr.Addr{}, err
	}
	n := int(binary.BigEndian.Uint16(size[:]))
	if n > len(b) {
		if _, err := io.CopyN(io.Discard, d.r, int64(n)); err != nil {
			return 0, addr.Addr{}, err
		}
		return 0, peer, io.ErrShortBuffer
	}
	if _, err := io.ReadFull(d.r, b[:n]); err != nil {
		return 0, addr.Addr{}, err
	}
	d.idle.touch()
	return n, peer, nil
}

func (d *datagramConn) WritePacket(p []byte, peer addr.Addr) error {
	if len(p) > 0xFFFF {
		return errors.New("juicity: datagram too large")
	}
	frame := bufpool.Get(1 + 1 + 1 + 255 + 2 + 2 + len(p) + 24)
	defer bufpool.Put(frame)
	out := frame[:0]
	d.wmu.Lock()
	defer d.wmu.Unlock()
	var err error
	if d.client && !d.begun {
		if out, err = appendHeader(out, netUDP, peer); err != nil {
			return err
		}
	}
	if out, err = appendAddr(out, peer); err != nil {
		return err
	}
	out = binary.BigEndian.AppendUint16(out, uint16(len(p)))
	out = append(out, p...)
	if _, err = d.s.Write(out); err != nil {
		return err
	}
	d.begun = true
	d.idle.touch()
	return nil
}

func (d *datagramConn) SetReadDeadline(t time.Time) error { return d.s.SetReadDeadline(t) }

func (d *datagramConn) Close() error {
	var err error
	d.once.Do(func() {
		d.idle.stop()
		d.s.CancelRead(0)
		err = d.s.Close()
	})
	return err
}
