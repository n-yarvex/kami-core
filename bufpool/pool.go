package bufpool

import "math/bits"

const (
	minShift = 6
	maxShift = 17
	perClass = 32
)

var classes [maxShift - minShift + 1]chan []byte

func init() {
	for i := range classes {
		classes[i] = make(chan []byte, perClass)
	}
}

func Get(n int) []byte {
	if n <= 0 {
		return nil
	}
	shift := max(bits.Len(uint(n-1)), minShift)
	if shift > maxShift {
		return make([]byte, n)
	}
	select {
	case b := <-classes[shift-minShift]:
		return b[:n]
	default:
		return make([]byte, n, 1<<shift)
	}
}

func Put(b []byte) {
	c := cap(b)
	if c == 0 || c&(c-1) != 0 {
		return
	}
	shift := bits.Len(uint(c)) - 1
	if shift < minShift || shift > maxShift {
		return
	}
	select {
	case classes[shift-minShift] <- b[:c]:
	default:
	}
}
