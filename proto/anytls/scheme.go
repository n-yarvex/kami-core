package anytls

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"
)

const (
	checkMark   = -1
	maxStop     = 256
	maxSpans    = 64
	maxSpanSize = 0xFFFF
)

const defaultSchemeText = `stop=8
0=30-30
1=100-400
2=400-500,c,500-1000,c,500-1000,c,500-1000,c,500-1000
3=9-9,500-1000
4=500-1000
5=500-1000
6=500-1000
7=500-1000`

type span struct {
	lo, hi int
	check  bool
}

type scheme struct {
	text  string
	sum   string
	stop  int
	steps map[int][]span
}

func parseScheme(text string) (*scheme, error) {
	text = strings.ReplaceAll(text, "\r\n", "\n")
	kv := decodeKV([]byte(text))
	stop, err := strconv.Atoi(strings.TrimSpace(kv["stop"]))
	if err != nil || stop < 0 || stop > maxStop {
		return nil, errors.New("padding scheme: stop is missing or out of range")
	}
	s := &scheme{text: text, stop: stop, steps: map[int][]span{}}
	sum := md5.Sum([]byte(text))
	s.sum = hex.EncodeToString(sum[:])
	for k, v := range kv {
		if k == "stop" {
			continue
		}
		n, err := strconv.Atoi(k)
		if err != nil || n < 0 || n > maxStop {
			return nil, errors.New("padding scheme: bad packet index " + strconv.Quote(k))
		}
		var spans []span
		for _, tok := range strings.Split(v, ",") {
			tok = strings.TrimSpace(tok)
			if tok == "c" {
				spans = append(spans, span{check: true})
				continue
			}
			a, b, ok := strings.Cut(tok, "-")
			if !ok {
				continue
			}
			lo, e1 := strconv.Atoi(a)
			hi, e2 := strconv.Atoi(b)
			if e1 != nil || e2 != nil || lo <= 0 || hi <= 0 || lo > maxSpanSize || hi > maxSpanSize {
				continue
			}
			spans = append(spans, span{lo: min(lo, hi), hi: max(lo, hi)})
		}
		if len(spans) > maxSpans {
			return nil, errors.New("padding scheme: too many entries for packet " + k)
		}
		s.steps[n] = spans
	}
	return s, nil
}

func draw(lo, hi int) int {
	if lo == hi {
		return lo
	}
	var b [4]byte
	rand.Read(b[:])
	return lo + int(binary.BigEndian.Uint32(b[:])%uint32(hi-lo+1))
}

func (s *scheme) plan(n int) []int {
	spans := s.steps[n]
	out := make([]int, 0, len(spans))
	for _, sp := range spans {
		if sp.check {
			out = append(out, checkMark)
		} else {
			out = append(out, draw(sp.lo, sp.hi))
		}
	}
	return out
}

func (s *scheme) authPadding() int {
	for _, v := range s.plan(0) {
		if v != checkMark {
			return v
		}
	}
	return 0
}

var builtinScheme = func() *scheme {
	s, err := parseScheme(defaultSchemeText)
	if err != nil {
		panic(err)
	}
	return s
}()
