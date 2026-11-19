package ss2022

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/n-yarvex/kami-core/addr"
)

const xnonce = chacha20poly1305.NonceSizeX

var errDatagram = errors.New("ss2022: bad datagram")

type sessionID [8]byte

type datagramCodec struct {
	suite *suite
}

func newBody(kind byte, client *sessionID, peer addr.Addr, payload []byte) ([]byte, error) {
	target, err := peer.AppendSocks(nil)
	if err != nil {
		return nil, err
	}
	body := make([]byte, 0, 1+8+8+2+len(target)+len(payload))
	body = append(body, kind)
	body = append(body, stamp()...)
	if client != nil {
		body = append(body, client[:]...)
	}
	body = append(body, 0, 0)
	body = append(body, target...)
	return append(body, payload...), nil
}

func openBody(kind byte, wantClient bool, body []byte) (client sessionID, peer addr.Addr, payload []byte, err error) {
	need := 1 + 8 + 2
	if wantClient {
		need += 8
	}
	if len(body) < need || body[0] != kind || !fresh(time.Now(), int64(binary.BigEndian.Uint64(body[1:9]))) {
		return client, peer, nil, errDatagram
	}
	off := 9
	if wantClient {
		copy(client[:], body[off:off+8])
		off += 8
	}
	pad := int(binary.BigEndian.Uint16(body[off:]))
	off += 2 + pad
	if off > len(body) {
		return client, peer, nil, errDatagram
	}
	peer, used, err := addr.ParseSocks(body[off:])
	if err != nil {
		return client, peer, nil, errDatagram
	}
	return client, peer, body[off+used:], nil
}

type separate struct {
	session sessionID
	packet  uint64
}

func (h separate) bytes() (b [16]byte) {
	copy(b[:8], h.session[:])
	binary.BigEndian.PutUint64(b[8:], h.packet)
	return
}

func splitSeparate(b [16]byte) (h separate) {
	copy(h.session[:], b[:8])
	h.packet = binary.BigEndian.Uint64(b[8:])
	return
}

type outgoing struct {
	sepKey []byte
	layers [][]byte
	aead   cipher.AEAD
}

func (c *datagramCodec) pack(o *outgoing, h separate, body []byte) []byte {
	if c.suite.chacha {
		out := make([]byte, xnonce, xnonce+16+len(body)+16)
		rand.Read(out)
		plain := make([]byte, 0, 16+len(body))
		raw := h.bytes()
		plain = append(plain, raw[:]...)
		plain = append(plain, body...)
		return o.aead.Seal(out, out[:xnonce], plain, nil)
	}
	plain := h.bytes()
	out := make([]byte, 0, 16+16*len(o.layers)+len(body)+tag)
	enc := plain
	ecbSeal(o.sepKey, &enc)
	out = append(out, enc[:]...)
	for i := 0; i+1 < len(o.layers); i++ {
		blk := fingerprint(o.layers[i+1])
		for j := range blk {
			blk[j] ^= plain[j]
		}
		ecbSeal(o.layers[i], &blk)
		out = append(out, blk[:]...)
	}
	return o.aead.Seal(out, plain[4:16], body, nil)
}
