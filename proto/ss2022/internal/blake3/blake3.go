package blake3

import (
	"encoding/binary"
	"math/bits"
)

const (
	blockLen = 64
	chunkLen = 1024
)

const (
	flagChunkStart = 1 << iota
	flagChunkEnd
	flagParent
	flagRoot
	flagKeyed
	flagDeriveContext
	flagDeriveMaterial
)

var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

var schedule = [16]uint8{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

func mix(v *[16]uint32, a, b, c, d int, x, y uint32) {
	v[a] += v[b] + x
	v[d] = bits.RotateLeft32(v[d]^v[a], -16)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -12)
	v[a] += v[b] + y
	v[d] = bits.RotateLeft32(v[d]^v[a], -8)
	v[c] += v[d]
	v[b] = bits.RotateLeft32(v[b]^v[c], -7)
}

func round(v *[16]uint32, m *[16]uint32) {
	mix(v, 0, 4, 8, 12, m[0], m[1])
	mix(v, 1, 5, 9, 13, m[2], m[3])
	mix(v, 2, 6, 10, 14, m[4], m[5])
	mix(v, 3, 7, 11, 15, m[6], m[7])
	mix(v, 0, 5, 10, 15, m[8], m[9])
	mix(v, 1, 6, 11, 12, m[10], m[11])
	mix(v, 2, 7, 8, 13, m[12], m[13])
	mix(v, 3, 4, 9, 14, m[14], m[15])
}

func compress(cv *[8]uint32, m [16]uint32, counter uint64, n, flags uint32) [16]uint32 {
	v := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter), uint32(counter >> 32), n, flags,
	}
	for r := 0; r < 7; r++ {
		round(&v, &m)
		if r < 6 {
			var next [16]uint32
			for i, p := range schedule {
				next[i] = m[p]
			}
			m = next
		}
	}
	for i := 0; i < 8; i++ {
		v[i] ^= v[i+8]
		v[i+8] ^= cv[i]
	}
	return v
}

func words(b []byte) (m [16]uint32) {
	var pad [blockLen]byte
	copy(pad[:], b)
	for i := range m {
		m[i] = binary.LittleEndian.Uint32(pad[4*i:])
	}
	return
}

type node struct {
	cv      [8]uint32
	block   [16]uint32
	counter uint64
	n       uint32
	flags   uint32
}

func (nd *node) chain() (out [8]uint32) {
	full := compress(&nd.cv, nd.block, nd.counter, nd.n, nd.flags)
	copy(out[:], full[:8])
	return
}

func (nd *node) read(dst []byte) {
	for ctr := uint64(0); len(dst) > 0; ctr++ {
		full := compress(&nd.cv, nd.block, ctr, nd.n, nd.flags|flagRoot)
		var raw [blockLen]byte
		for i, w := range full {
			binary.LittleEndian.PutUint32(raw[4*i:], w)
		}
		dst = dst[copy(dst, raw[:]):]
	}
}

type chunk struct {
	cv      [8]uint32
	counter uint64
	buf     [blockLen]byte
	filled  int
	blocks  int
	flags   uint32
}

func (c *chunk) size() int { return blockLen*c.blocks + c.filled }

func (c *chunk) start() uint32 {
	if c.blocks == 0 {
		return flagChunkStart
	}
	return 0
}

func (c *chunk) write(p []byte) {
	for len(p) > 0 {
		if c.filled == blockLen {
			full := compress(&c.cv, words(c.buf[:]), c.counter, blockLen, c.flags|c.start())
			copy(c.cv[:], full[:8])
			c.blocks++
			c.filled = 0
		}
		n := copy(c.buf[c.filled:], p)
		c.filled += n
		p = p[n:]
	}
}

func (c *chunk) node() node {
	return node{
		cv:      c.cv,
		block:   words(c.buf[:c.filled]),
		counter: c.counter,
		n:       uint32(c.filled),
		flags:   c.flags | c.start() | flagChunkEnd,
	}
}

type hasher struct {
	key   [8]uint32
	cur   chunk
	stack [][8]uint32
	flags uint32
}

func newHasher(key [8]uint32, flags uint32) *hasher {
	return &hasher{key: key, cur: chunk{cv: key, flags: flags}, flags: flags}
}

func (h *hasher) parent(left, right [8]uint32) node {
	var m [16]uint32
	copy(m[:8], left[:])
	copy(m[8:], right[:])
	return node{cv: h.key, block: m, n: blockLen, flags: h.flags | flagParent}
}

func (h *hasher) write(p []byte) {
	for len(p) > 0 {
		if h.cur.size() == chunkLen {
			cv := h.cur.node()
			done := cv.chain()
			total := h.cur.counter + 1
			for t := total; t&1 == 0; t >>= 1 {
				top := h.stack[len(h.stack)-1]
				h.stack = h.stack[:len(h.stack)-1]
				pn := h.parent(top, done)
				done = pn.chain()
			}
			h.stack = append(h.stack, done)
			h.cur = chunk{cv: h.key, counter: total, flags: h.flags}
		}
		n := min(chunkLen-h.cur.size(), len(p))
		h.cur.write(p[:n])
		p = p[n:]
	}
}

func (h *hasher) finish(dst []byte) {
	root := h.cur.node()
	for i := len(h.stack) - 1; i >= 0; i-- {
		root = h.parent(h.stack[i], root.chain())
	}
	root.read(dst)
}

func Sum(dst, data []byte) {
	h := newHasher(iv, 0)
	h.write(data)
	h.finish(dst)
}

func DeriveKey(dst []byte, context string, material ...[]byte) {
	var ck [32]byte
	ch := newHasher(iv, flagDeriveContext)
	ch.write([]byte(context))
	ch.finish(ck[:])
	var key [8]uint32
	for i := range key {
		key[i] = binary.LittleEndian.Uint32(ck[4*i:])
	}
	h := newHasher(key, flagDeriveMaterial)
	for _, m := range material {
		h.write(m)
	}
	h.finish(dst)
}
