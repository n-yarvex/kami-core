package nakis

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"math/big"
	mrand "math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

var errMangled = errors.New("nakis: malformed udp record")

func appendRecord(b []byte, peer addr.Addr, data []byte) ([]byte, error) {
	if len(data) > 0xFFFF {
		return nil, errMangled
	}
	b, err := peer.AppendSocks(b)
	if err != nil {
		return nil, errMangled
	}
	b = binary.BigEndian.AppendUint16(b, uint16(len(data)))
	return append(b, data...), nil
}

func readPeer(r *bufio.Reader) (addr.Addr, error) {
	var raw [1 + 1 + 255 + 2]byte
	if _, err := io.ReadFull(r, raw[:1]); err != nil {
		return addr.Addr{}, err
	}
	n, got := 0, 1
	switch raw[0] {
	case 1:
		n = 1 + 4 + 2
	case 4:
		n = 1 + 16 + 2
	case 3:
		if _, err := io.ReadFull(r, raw[1:2]); err != nil {
			return addr.Addr{}, midRecord(err)
		}
		n, got = 2+int(raw[1])+2, 2
	default:
		return addr.Addr{}, errMangled
	}
	if _, err := io.ReadFull(r, raw[got:n]); err != nil {
		return addr.Addr{}, midRecord(err)
	}
	peer, _, err := addr.ParseSocks(raw[:n])
	if err != nil {
		return addr.Addr{}, errMangled
	}
	return peer, nil
}

func readRecord(r *bufio.Reader, buf []byte) (addr.Addr, []byte, error) {
	peer, err := readPeer(r)
	if err != nil {
		return peer, nil, err
	}
	var lb [2]byte
	if _, err := io.ReadFull(r, lb[:]); err != nil {
		return peer, nil, midRecord(err)
	}
	n := int(binary.BigEndian.Uint16(lb[:]))
	if _, err := io.ReadFull(r, buf[:n]); err != nil {
		return peer, nil, midRecord(err)
	}
	return peer, buf[:n], nil
}

func midRecord(err error) error {
	if errors.Is(err, ErrNap) || errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: cut short", errMangled)
	}
	return err
}

func randBelow(n int) int {
	v, err := rand.Int(rand.Reader, big.NewInt(int64(n)))
	if err != nil {
		return mrand.IntN(n)
	}
	return int(v.Int64())
}

func sendWithPad(mc *Tunnel, payload []byte) error {
	wire := bufpool.Get(Headroom + len(payload))
	defer bufpool.Put(wire)
	copy(wire[Headroom:], payload)
	return mc.SendWirePad(wire, 4+randBelow(udpPadMax))
}

type jitterMux struct {
	jitter time.Duration
	send   func([]byte) error

	mu     sync.Mutex
	cond   *sync.Cond
	q      [][]byte
	size   int
	closed bool
	failed atomic.Bool
	stop   chan struct{}
	done   chan struct{}
}

func newJitterMux(jitter time.Duration, send func([]byte) error) *jitterMux {
	m := &jitterMux{jitter: jitter, send: send, stop: make(chan struct{}), done: make(chan struct{})}
	m.cond = sync.NewCond(&m.mu)
	go m.run()
	return m
}

func (m *jitterMux) push(rec []byte) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.closed || m.failed.Load() || m.size+len(rec) > udpQueueMax {
		bufpool.Put(rec)
		return false
	}
	m.q = append(m.q, rec)
	m.size += len(rec)
	m.cond.Signal()
	return true
}

func (m *jitterMux) nap() {
	t := time.NewTimer(time.Duration(mrand.Int64N(int64(m.jitter))) + time.Microsecond)
	defer t.Stop()
	select {
	case <-t.C:
	case <-m.stop:
	}
}

func (m *jitterMux) take() []byte {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.q) == 0 {
		return nil
	}
	var out []byte
	i := 0
	for i < len(m.q) && (i == 0 || len(out)+len(m.q[i]) <= udpBatchMax) {
		out = append(out, m.q[i]...)
		m.size -= len(m.q[i])
		bufpool.Put(m.q[i])
		i++
	}
	m.q = m.q[:copy(m.q, m.q[i:])]
	return out
}

func (m *jitterMux) abandon() {
	m.failed.Store(true)
	m.mu.Lock()
	for _, p := range m.q {
		bufpool.Put(p)
	}
	m.q, m.size = nil, 0
	m.mu.Unlock()
}

func (m *jitterMux) run() {
	defer close(m.done)
	for {
		m.mu.Lock()
		for len(m.q) == 0 && !m.closed {
			m.cond.Wait()
		}
		empty := len(m.q) == 0
		m.mu.Unlock()
		if empty {
			return
		}
		if m.jitter > 0 {
			m.nap()
		}
		for {
			batch := m.take()
			if batch == nil {
				break
			}
			if err := m.send(batch); err != nil {
				m.abandon()
				return
			}
		}
	}
}

func (m *jitterMux) close() {
	m.mu.Lock()
	if !m.closed {
		m.closed = true
		close(m.stop)
	}
	m.cond.Broadcast()
	m.mu.Unlock()
	<-m.done
}
