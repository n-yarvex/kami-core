package masque

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/quic-go/quic-go/quicvarint"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

const (
	capsuleDatagram http3.CapsuleType = 0
	inboxDepth                        = 256
)

type packet struct {
	data []byte
	from addr.Addr
}

type target struct {
	peer  addr.Addr
	st    h3Stream
	dg    bool
	recv  bool
	wmu   sync.Mutex
	last  atomic.Int64
	ready chan struct{}
	err   error
}

func (t *target) send(p []byte) error {
	buf := bufpool.Get(len(p) + 16)
	defer bufpool.Put(buf)
	out := append(buf[:0], 0)
	out = append(out, p...)
	if t.dg {
		err := t.st.SendDatagram(out)
		if err == nil {
			return nil
		}
		var big *quic.DatagramTooLargeError
		if !errors.As(err, &big) {
			return err
		}
	}
	frame := make([]byte, 0, len(out)+10)
	frame = quicvarint.Append(frame, uint64(capsuleDatagram))
	frame = quicvarint.Append(frame, uint64(len(out)))
	frame = append(frame, out...)
	t.wmu.Lock()
	_, err := t.st.Write(frame)
	t.wmu.Unlock()
	return err
}

func (t *target) close() {
	t.st.CancelRead(codeConnect)
	t.st.CancelWrite(codeConnect)
}

func contextZero(b []byte) ([]byte, bool) {
	id, n, err := quicvarint.Parse(b)
	if err != nil || id != 0 {
		return nil, false
	}
	return b[n:], true
}

type flow struct {
	open func(ctx context.Context, dest addr.Addr) (*target, error)
	nat  time.Duration

	mu     sync.Mutex
	subs   map[string]*target
	only   *target
	inbox  chan packet
	done   chan struct{}
	once   sync.Once
	rdl    atomic.Pointer[time.Time]
	wake   chan struct{}
	idle   *idler
	closed atomic.Bool
}

func newFlow(nat time.Duration, open func(context.Context, addr.Addr) (*target, error)) *flow {
	f := &flow{
		open:  open,
		nat:   nat,
		subs:  map[string]*target{},
		inbox: make(chan packet, inboxDepth),
		done:  make(chan struct{}),
		wake:  make(chan struct{}, 1),
	}
	f.idle = newIdler(nat, func() { f.Close() })
	return f
}

func (f *flow) adopt(t *target) {
	t.last.Store(time.Now().UnixNano())
	go f.receiveDatagrams(t)
	go f.receiveCapsules(t)
}

func (f *flow) deliver(t *target, payload []byte) {
	p, ok := contextZero(payload)
	if !ok {
		return
	}
	f.idle.touch()
	t.last.Store(time.Now().UnixNano())
	select {
	case f.inbox <- packet{data: append([]byte(nil), p...), from: t.peer}:
	case <-f.done:
	default:
	}
}

func (f *flow) receiveDatagrams(t *target) {
	if !t.recv {
		return
	}
	for {
		d, err := t.st.ReceiveDatagram(context.Background())
		if err != nil {
			return
		}
		f.deliver(t, d)
	}
}

func (f *flow) receiveCapsules(t *target) {
	defer f.drop(t)
	cp := http3.NewCapsuleParser(streamReader{t.st})
	for {
		typ, r, err := cp.Next()
		if err != nil {
			return
		}
		if typ != capsuleDatagram {
			if r.Discard() != nil {
				return
			}
			continue
		}
		body := make([]byte, r.Remaining())
		if _, err := io.ReadFull(r, body); err != nil {
			return
		}
		f.deliver(t, body)
	}
}

type streamReader struct{ s h3Stream }

func (r streamReader) Read(p []byte) (int, error) { return r.s.Read(p) }

func (f *flow) drop(t *target) {
	f.mu.Lock()
	for k, v := range f.subs {
		if v == t {
			delete(f.subs, k)
		}
	}
	single := f.only == t
	f.mu.Unlock()
	t.close()
	if single {
		f.Close()
	}
}

func (f *flow) lookup(ctx context.Context, peer addr.Addr) (*target, error) {
	if f.only != nil {
		return f.only, nil
	}
	key := peer.String()
	f.mu.Lock()
	if t, ok := f.subs[key]; ok {
		f.mu.Unlock()
		<-t.ready
		return t, t.err
	}
	if len(f.subs) >= maxFlowTargets {
		var oldest *target
		for _, v := range f.subs {
			if v.err == nil && (oldest == nil || v.last.Load() < oldest.last.Load()) {
				oldest = v
			}
		}
		if oldest != nil {
			go f.drop(oldest)
		}
	}
	t := &target{peer: peer, ready: make(chan struct{})}
	f.subs[key] = t
	f.mu.Unlock()
	made, err := f.open(ctx, peer)
	if err != nil {
		t.err = err
		f.mu.Lock()
		delete(f.subs, key)
		f.mu.Unlock()
		close(t.ready)
		return nil, err
	}
	t.st, t.dg, t.recv = made.st, made.dg, made.recv
	close(t.ready)
	f.adopt(t)
	return t, nil
}

func (f *flow) WritePacket(p []byte, peer addr.Addr) error {
	if f.closed.Load() {
		return net.ErrClosed
	}
	ctx, cancel := context.WithTimeout(context.Background(), dialPatience)
	defer cancel()
	t, err := f.lookup(ctx, peer)
	if err != nil {
		return err
	}
	f.idle.touch()
	t.last.Store(time.Now().UnixNano())
	return t.send(p)
}

func (f *flow) ReadPacket(b []byte) (int, addr.Addr, error) {
	for {
		var timeout <-chan time.Time
		if dl := f.rdl.Load(); dl != nil && !dl.IsZero() {
			d := time.Until(*dl)
			if d <= 0 {
				return 0, addr.Addr{}, os.ErrDeadlineExceeded
			}
			tm := time.NewTimer(d)
			defer tm.Stop()
			timeout = tm.C
		}
		select {
		case p := <-f.inbox:
			if len(p.data) > len(b) {
				return 0, p.from, io.ErrShortBuffer
			}
			return copy(b, p.data), p.from, nil
		case <-f.done:
			return 0, addr.Addr{}, net.ErrClosed
		case <-timeout:
			return 0, addr.Addr{}, os.ErrDeadlineExceeded
		case <-f.wake:
		}
	}
}

func (f *flow) SetReadDeadline(t time.Time) error {
	f.rdl.Store(&t)
	select {
	case f.wake <- struct{}{}:
	default:
	}
	return nil
}

func (f *flow) Close() error {
	f.once.Do(func() {
		f.closed.Store(true)
		close(f.done)
		f.idle.stop()
		f.mu.Lock()
		all := make([]*target, 0, len(f.subs)+1)
		for _, t := range f.subs {
			if t.st != nil {
				all = append(all, t)
			}
		}
		if f.only != nil {
			all = append(all, f.only)
		}
		f.mu.Unlock()
		for _, t := range all {
			t.close()
		}
	})
	return nil
}

type idler struct {
	last  atomic.Int64
	span  time.Duration
	timer *time.Timer
	fire  func()
}

func newIdler(span time.Duration, fire func()) *idler {
	i := &idler{span: span, fire: fire}
	i.last.Store(time.Now().UnixNano())
	i.timer = time.AfterFunc(span, i.check)
	return i
}

func (i *idler) touch() { i.last.Store(time.Now().UnixNano()) }

func (i *idler) check() {
	left := i.span - time.Duration(time.Now().UnixNano()-i.last.Load())
	if left > 0 {
		i.timer.Reset(left)
		return
	}
	i.fire()
}

func (i *idler) stop() { i.timer.Stop() }
