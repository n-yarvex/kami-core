package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/bufpool"
)

const tag = 16

var errCorrupt = errors.New("ss2022: stream is corrupt")

type chunkReader struct {
	src   io.Reader
	aead  cipher.AEAD
	ctr   counter
	first int
	buf   []byte
	rest  []byte
}

func (r *chunkReader) arm(aead cipher.AEAD, first int) {
	r.aead = aead
	r.first = first
	r.ctr = counter{}
	if r.buf == nil {
		r.buf = bufpool.Get(maxChunk + tag)
	}
}

func (r *chunkReader) open(n int) ([]byte, error) {
	if _, err := io.ReadFull(r.src, r.buf[:n+tag]); err != nil {
		return nil, err
	}
	out, err := r.aead.Open(r.buf[:0], r.ctr.take(), r.buf[:n+tag], nil)
	if err != nil {
		return nil, errCorrupt
	}
	return out, nil
}

func (r *chunkReader) Read(p []byte) (int, error) {
	for len(r.rest) == 0 {
		n := r.first
		r.first = -1
		if n < 0 {
			hdr, err := r.open(2)
			if err != nil {
				return 0, err
			}
			n = int(binary.BigEndian.Uint16(hdr))
		}
		if n == 0 {
			continue
		}
		body, err := r.open(n)
		if err != nil {
			if err == io.EOF {
				err = io.ErrUnexpectedEOF
			}
			return 0, err
		}
		r.rest = body
	}
	n := copy(p, r.rest)
	r.rest = r.rest[n:]
	return n, nil
}

func (r *chunkReader) release() {
	if r.buf != nil {
		bufpool.Put(r.buf)
		r.buf = nil
	}
}

type chunkWriter struct {
	aead cipher.AEAD
	ctr  counter
}

func (w *chunkWriter) frame(dst, p []byte) []byte {
	var n [2]byte
	binary.BigEndian.PutUint16(n[:], uint16(len(p)))
	dst = w.aead.Seal(dst, w.ctr.take(), n[:], nil)
	return w.aead.Seal(dst, w.ctr.take(), p, nil)
}

type tunnel struct {
	net.Conn
	suite *suite

	wmu     sync.Mutex
	writer  chunkWriter
	opened  bool
	opening func(first []byte) (head []byte, used int, err error)
	wake    chan struct{}
	wait    time.Duration

	rmu    sync.Mutex
	rd     chunkReader
	rinit  func() error
	rerr   error
	closed sync.Once
}

func (t *tunnel) Write(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if !t.opened {
		head, used, err := t.opening(p)
		if err != nil {
			return 0, err
		}
		out := t.pack(head, p[used:])
		if _, err = t.Conn.Write(out); err != nil {
			return 0, err
		}
		t.opened = true
		if t.wake != nil {
			close(t.wake)
		}
		return len(p), nil
	}
	done := 0
	for done < len(p) {
		n := min(len(p)-done, maxChunk)
		out := bufpool.Get(2 + tag + n + tag)
		out = t.writer.frame(out[:0], p[done:done+n])
		_, err := t.Conn.Write(out)
		bufpool.Put(out[:cap(out)])
		if err != nil {
			return done, err
		}
		done += n
	}
	return done, nil
}

func (t *tunnel) pack(out, p []byte) []byte {
	for len(p) > 0 {
		n := min(len(p), maxChunk)
		out = t.writer.frame(out, p[:n])
		p = p[n:]
	}
	return out
}

func (t *tunnel) begin() error {
	t.wmu.Lock()
	defer t.wmu.Unlock()
	if t.opened {
		return nil
	}
	head, _, err := t.opening(nil)
	if err != nil {
		return err
	}
	if _, err := t.Conn.Write(head); err != nil {
		return err
	}
	t.opened = true
	if t.wake != nil {
		close(t.wake)
	}
	return nil
}

func (t *tunnel) Read(p []byte) (int, error) {
	t.rmu.Lock()
	defer t.rmu.Unlock()
	if t.rerr != nil {
		return 0, t.rerr
	}
	if t.rinit != nil {
		if t.wake != nil {
			timer := time.NewTimer(t.wait)
			select {
			case <-t.wake:
			case <-timer.C:
			}
			timer.Stop()
			if err := t.begin(); err != nil {
				t.rerr = err
				return 0, err
			}
		}
		init := t.rinit
		t.rinit = nil
		if err := init(); err != nil {
			t.rerr = err
			return 0, err
		}
	}
	n, err := t.rd.Read(p)
	if err != nil {
		t.rerr = err
	}
	return n, err
}

func (t *tunnel) CloseWrite() error {
	if t.wake != nil {
		if err := t.begin(); err != nil {
			return err
		}
	}
	if cw, ok := t.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("ss2022: half close unsupported")
}

func (t *tunnel) Close() error {
	err := t.Conn.Close()
	t.closed.Do(func() {
		go func() {
			t.rmu.Lock()
			t.rd.release()
			t.rerr = net.ErrClosed
			t.rmu.Unlock()
		}()
	})
	return err
}

func randomBytes(n int) []byte {
	b := make([]byte, n)
	rand.Read(b)
	return b
}

func randBelow(n int) int {
	var b [2]byte
	rand.Read(b[:])
	return int(binary.BigEndian.Uint16(b[:])) % n
}
