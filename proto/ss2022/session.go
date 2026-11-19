package ss2022

import (
	"crypto/subtle"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"time"

	"github.com/n-yarvex/kami-core/addr"
)

const firstFlightWait = 25 * time.Millisecond

var errRefused = errors.New("ss2022: request refused")

func stamp() []byte {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], uint64(time.Now().Unix()))
	return b[:]
}

func dialTunnel(conn net.Conn, s *suite, chain [][]byte, dest addr.Addr) *tunnel {
	user := chain[len(chain)-1]
	var sent []byte
	t := &tunnel{Conn: conn, suite: s, wake: make(chan struct{}), wait: firstFlightWait}
	t.rd.src = conn
	t.opening = func(first []byte) ([]byte, int, error) {
		salt := randomBytes(s.keyLen)
		sent = salt
		t.writer = chunkWriter{aead: s.seal(derive(ctxSession, user, salt))}
		target, err := dest.AppendSocks(nil)
		if err != nil {
			return nil, 0, err
		}
		pad := randBelow(maxPadding + 1)
		if len(first) == 0 && pad == 0 {
			pad = 1 + randBelow(maxPadding)
		}
		used := min(len(first), maxChunk-len(target)-2-pad)
		body := make([]byte, 0, len(target)+2+pad+used)
		body = append(body, target...)
		body = binary.BigEndian.AppendUint16(body, uint16(pad))
		body = append(body, randomBytes(pad)...)
		body = append(body, first[:used]...)

		head := make([]byte, 0, len(salt)+len(chain)*16+11+tag+len(body)+tag+len(first))
		head = append(head, salt...)
		for i := 0; i+1 < len(chain); i++ {
			block := fingerprint(chain[i+1])
			ecbSeal(derive(ctxIdentity, chain[i], salt), &block)
			head = append(head, block[:]...)
		}
		fixed := append([]byte{kindRequest}, stamp()...)
		fixed = binary.BigEndian.AppendUint16(fixed, uint16(len(body)))
		head = t.writer.aead.Seal(head, t.writer.ctr.take(), fixed, nil)
		head = t.writer.aead.Seal(head, t.writer.ctr.take(), body, nil)
		return head, used, nil
	}
	t.rinit = func() error {
		raw := make([]byte, s.keyLen+1+8+s.keyLen+2+tag)
		if _, err := io.ReadFull(conn, raw); err != nil {
			return err
		}
		aead := s.seal(derive(ctxSession, user, raw[:s.keyLen]))
		var ctr counter
		hdr, err := aead.Open(nil, ctr.take(), raw[s.keyLen:], nil)
		if err != nil {
			return errCorrupt
		}
		if hdr[0] != kindResponse || !fresh(time.Now(), int64(binary.BigEndian.Uint64(hdr[1:9]))) ||
			subtle.ConstantTimeCompare(hdr[9:9+s.keyLen], sent) != 1 {
			return errCorrupt
		}
		t.rd.arm(aead, int(binary.BigEndian.Uint16(hdr[9+s.keyLen:])))
		t.rd.ctr = ctr
		return nil
	}
	return t
}

type account struct {
	name string
	key  []byte
}

type acceptor struct {
	suite   *suite
	key     []byte
	users   map[[16]byte]*account
	salts   *saltCache
	timeout time.Duration
}

func (a *acceptor) quarantine(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		cw.CloseWrite()
	}
	conn.SetReadDeadline(time.Now().Add(a.timeout))
	io.Copy(io.Discard, io.LimitReader(conn, 1<<20))
	conn.Close()
}

func (a *acceptor) accept(conn net.Conn) (*tunnel, string, addr.Addr, error) {
	s := a.suite
	conn.SetReadDeadline(time.Now().Add(a.timeout))
	salt := make([]byte, s.keyLen)
	if _, err := io.ReadFull(conn, salt); err != nil {
		return nil, "", addr.Addr{}, err
	}
	key, name := a.key, ""
	if a.users != nil {
		var block [16]byte
		if _, err := io.ReadFull(conn, block[:]); err != nil {
			return nil, "", addr.Addr{}, err
		}
		ecbOpen(derive(ctxIdentity, a.key, salt), &block)
		who, ok := a.users[block]
		if !ok {
			return nil, "", addr.Addr{}, errRefused
		}
		key, name = who.key, who.name
	}
	raw := make([]byte, 11+tag)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, "", addr.Addr{}, err
	}
	aead := s.seal(derive(ctxSession, key, salt))
	var ctr counter
	fixed, err := aead.Open(nil, ctr.take(), raw, nil)
	if err != nil || fixed[0] != kindRequest || !fresh(time.Now(), int64(binary.BigEndian.Uint64(fixed[1:9]))) {
		return nil, "", addr.Addr{}, errRefused
	}
	if !a.salts.claim(salt, time.Now()) {
		return nil, "", addr.Addr{}, errRefused
	}
	size := int(binary.BigEndian.Uint16(fixed[9:11]))
	raw = make([]byte, size+tag)
	if _, err := io.ReadFull(conn, raw); err != nil {
		return nil, "", addr.Addr{}, err
	}
	body, err := aead.Open(nil, ctr.take(), raw, nil)
	if err != nil {
		return nil, "", addr.Addr{}, errRefused
	}
	dest, used, err := addr.ParseSocks(body)
	if err != nil || len(body) < used+2 {
		return nil, "", addr.Addr{}, errRefused
	}
	pad := int(binary.BigEndian.Uint16(body[used:]))
	if used+2+pad > len(body) || (used+2+pad == len(body) && pad == 0) {
		return nil, "", addr.Addr{}, errRefused
	}
	conn.SetReadDeadline(time.Time{})

	t := &tunnel{Conn: conn, suite: s}
	t.rd.src = conn
	t.rd.arm(aead, -1)
	t.rd.ctr = ctr
	t.rd.rest = body[used+2+pad:]
	t.opening = func(first []byte) ([]byte, int, error) {
		out := randomBytes(s.keyLen)
		t.writer = chunkWriter{aead: s.seal(derive(ctxSession, key, out))}
		n := min(len(first), maxChunk)
		fixed := append([]byte{kindResponse}, stamp()...)
		fixed = append(fixed, salt...)
		fixed = binary.BigEndian.AppendUint16(fixed, uint16(n))
		head := make([]byte, 0, len(out)+len(fixed)+tag+n+tag)
		head = t.writer.aead.Seal(append(head, out...), t.writer.ctr.take(), fixed, nil)
		head = t.writer.aead.Seal(head, t.writer.ctr.take(), first[:n], nil)
		return head, n, nil
	}
	return t, name, dest, nil
}
