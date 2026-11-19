package noise

import (
	"crypto/rand"
	"encoding/binary"
	mrand "math/rand/v2"
	"sync/atomic"
	"time"
)

const letters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"

func span(lo, hi int) int {
	if hi <= lo {
		return lo
	}
	return lo + mrand.IntN(hi-lo+1)
}

func (it *itemPlan) delay() time.Duration {
	if it.dmax <= it.dmin {
		return it.dmin
	}
	return it.dmin + time.Duration(mrand.Int64N(int64(it.dmax-it.dmin)+1))
}

func (it *itemPlan) build(dst []byte, counter *atomic.Uint32) []byte {
	dst = dst[:0]
	switch it.kind {
	case kFixed:
		return append(dst, it.fixed...)
	case kRandom:
		n := span(it.min, it.max)
		dst = grow(dst, n)
		rand.Read(dst)
		if it.lo != 0 || it.hi != 255 {
			w := int(it.hi) - int(it.lo) + 1
			for i := range dst {
				dst[i] = it.lo + byte(int(dst[i])%w)
			}
		}
		return dst
	}
	for _, s := range it.segs {
		switch s.kind {
		case sBytes:
			dst = append(dst, s.data...)
		case sStamp:
			dst = binary.BigEndian.AppendUint32(dst, uint32(time.Now().Unix()))
		case sCounter:
			dst = binary.BigEndian.AppendUint32(dst, counter.Add(1))
		case sNonce:
			at := len(dst)
			dst = grow(dst, at+8)
			rand.Read(dst[at:])
		default:
			n := span(s.min, s.max)
			at := len(dst)
			dst = grow(dst, at+n)
			part := dst[at:]
			rand.Read(part)
			switch s.kind {
			case sASCII:
				for i := range part {
					part[i] = letters[int(part[i])%len(letters)]
				}
			case sDigit:
				for i := range part {
					part[i] = '0' + part[i]%10
				}
			}
		}
	}
	return dst
}

func grow(b []byte, n int) []byte {
	if cap(b) >= n {
		return b[:n]
	}
	nb := make([]byte, n, max(n, 2*cap(b)))
	copy(nb, b)
	return nb
}
