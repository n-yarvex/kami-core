package noise

import (
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	DefaultSizeCap  = 1200
	MaxDelayMS      = 5000
	DefaultMaxPeers = 4096
	DefaultAmpCap   = 0.5
)

type Segment struct {
	Type    string `json:"type"`
	Bytes   string `json:"bytes,omitempty"`
	MinSize int    `json:"min_size,omitempty"`
	MaxSize int    `json:"max_size,omitempty"`
}

type Item struct {
	Packet       string    `json:"packet,omitempty"`
	RandMin      int       `json:"rand_min,omitempty"`
	RandMax      int       `json:"rand_max,omitempty"`
	RandRangeMin int       `json:"rand_range_min,omitempty"`
	RandRangeMax int       `json:"rand_range_max,omitempty"`
	Segments     []Segment `json:"segments,omitempty"`
	DelayMin     int       `json:"delay_min,omitempty"`
	DelayMax     int       `json:"delay_max,omitempty"`
}

type Config struct {
	ResetMin int      `json:"reset_min,omitempty"`
	ResetMax int      `json:"reset_max,omitempty"`
	Items    []Item   `json:"items"`
	SizeCap  int      `json:"size_cap,omitempty"`
	MaxPeers int      `json:"max_peers,omitempty"`
	AmpCap   *float64 `json:"amp_cap,omitempty"`
}

type kind uint8

const (
	kFixed kind = iota
	kRandom
	kSegments
)

type segKind uint8

const (
	sBytes segKind = iota
	sRandom
	sASCII
	sDigit
	sStamp
	sCounter
	sNonce
)

type segPlan struct {
	kind     segKind
	data     []byte
	min, max int
}

type itemPlan struct {
	kind       kind
	fixed      []byte
	min, max   int
	lo, hi     byte
	segs       []segPlan
	dmin, dmax time.Duration
	top        int
}

type Plan struct {
	items    []itemPlan
	resetMin time.Duration
	resetMax time.Duration
	maxPeers int
	ampCap   float64
	async    bool
	lo, hi   int
	dlo, dhi time.Duration
}

var segNames = map[string]segKind{
	"bytes":        sBytes,
	"random":       sRandom,
	"random_ascii": sASCII,
	"random_digit": sDigit,
	"timestamp":    sStamp,
	"counter":      sCounter,
	"nonce":        sNonce,
}

func (c *Config) Compile() (*Plan, error) {
	if c == nil {
		return nil, errors.New("noise: nil config")
	}
	if len(c.Items) == 0 {
		return nil, errors.New("noise: items must not be empty")
	}
	if c.ResetMin < 0 || c.ResetMax < 0 || c.ResetMin > c.ResetMax {
		return nil, fmt.Errorf("noise: reset_min %d / reset_max %d invalid", c.ResetMin, c.ResetMax)
	}
	limit := c.SizeCap
	if limit == 0 {
		limit = DefaultSizeCap
	}
	if limit < 1 || limit > 65000 {
		return nil, fmt.Errorf("noise: size_cap %d out of range", limit)
	}
	p := &Plan{
		resetMin: time.Duration(c.ResetMin) * time.Second,
		resetMax: time.Duration(c.ResetMax) * time.Second,
		maxPeers: c.MaxPeers,
		ampCap:   DefaultAmpCap,
	}
	if p.maxPeers == 0 {
		p.maxPeers = DefaultMaxPeers
	}
	if p.maxPeers < 1 {
		return nil, errors.New("noise: max_peers must be positive")
	}
	if c.AmpCap != nil {
		if *c.AmpCap < 0 || *c.AmpCap > 3 {
			return nil, errors.New("noise: amp_cap must be within 0..3")
		}
		p.ampCap = *c.AmpCap
	}
	p.lo = int(^uint(0) >> 1)
	p.dlo = time.Duration(1 << 62)
	for i := range c.Items {
		ip, err := compileItem(&c.Items[i], limit)
		if err != nil {
			return nil, fmt.Errorf("noise: item %d: %w", i, err)
		}
		if ip.dmax > 0 {
			p.async = true
		}
		p.lo = min(p.lo, ip.low())
		p.hi = max(p.hi, ip.top)
		p.dlo = min(p.dlo, ip.dmin)
		p.dhi = max(p.dhi, ip.dmax)
		p.items = append(p.items, ip)
	}
	return p, nil
}

func (it *itemPlan) low() int {
	switch it.kind {
	case kFixed:
		return len(it.fixed)
	case kRandom:
		return it.min
	}
	n := 0
	for _, s := range it.segs {
		switch s.kind {
		case sBytes:
			n += len(s.data)
		case sRandom, sASCII, sDigit:
			n += s.min
		case sStamp, sCounter:
			n += 4
		case sNonce:
			n += 8
		}
	}
	return n
}

func compileItem(it *Item, limit int) (itemPlan, error) {
	var ip itemPlan
	if it.DelayMin < 0 || it.DelayMax < it.DelayMin || it.DelayMax > MaxDelayMS {
		return ip, fmt.Errorf("delay %d..%d ms invalid (cap %d)", it.DelayMin, it.DelayMax, MaxDelayMS)
	}
	ip.dmin = time.Duration(it.DelayMin) * time.Millisecond
	ip.dmax = time.Duration(it.DelayMax) * time.Millisecond
	forms := 0
	if it.Packet != "" {
		forms++
	}
	if it.RandMax > 0 || it.RandMin > 0 {
		forms++
	}
	if len(it.Segments) > 0 {
		forms++
	}
	if forms != 1 {
		return ip, errors.New("exactly one of packet, rand_*, segments must be given")
	}
	switch {
	case it.Packet != "":
		raw, err := hex.DecodeString(strings.TrimPrefix(it.Packet, "0x"))
		if err != nil {
			return ip, fmt.Errorf("packet: %w", err)
		}
		if len(raw) == 0 || len(raw) > limit {
			return ip, fmt.Errorf("packet size %d outside 1..%d", len(raw), limit)
		}
		ip.kind, ip.fixed, ip.top = kFixed, raw, len(raw)
	case it.RandMax > 0 || it.RandMin > 0:
		if it.RandMin < 1 || it.RandMax < it.RandMin || it.RandMax > limit {
			return ip, fmt.Errorf("rand %d..%d outside 1..%d", it.RandMin, it.RandMax, limit)
		}
		lo, hi := it.RandRangeMin, it.RandRangeMax
		if hi == 0 && lo == 0 {
			hi = 255
		}
		if lo < 0 || hi > 255 || lo > hi {
			return ip, fmt.Errorf("rand_range %d..%d invalid", lo, hi)
		}
		ip.kind, ip.min, ip.max, ip.lo, ip.hi, ip.top = kRandom, it.RandMin, it.RandMax, byte(lo), byte(hi), it.RandMax
	default:
		ip.kind = kSegments
		for j, s := range it.Segments {
			k, ok := segNames[s.Type]
			if !ok {
				return ip, fmt.Errorf("segment %d: unknown type %q", j, s.Type)
			}
			sp := segPlan{kind: k}
			switch k {
			case sBytes:
				raw, err := hex.DecodeString(strings.TrimPrefix(s.Bytes, "0x"))
				if err != nil || len(raw) == 0 {
					return ip, fmt.Errorf("segment %d: bytes must be non-empty hex", j)
				}
				sp.data = raw
				ip.top += len(raw)
			case sRandom, sASCII, sDigit:
				if s.MinSize < 0 || s.MaxSize < s.MinSize || s.MaxSize < 1 {
					return ip, fmt.Errorf("segment %d: size %d..%d invalid", j, s.MinSize, s.MaxSize)
				}
				sp.min, sp.max = s.MinSize, s.MaxSize
				ip.top += s.MaxSize
			case sStamp, sCounter:
				ip.top += 4
			case sNonce:
				ip.top += 8
			}
			ip.segs = append(ip.segs, sp)
		}
		if ip.top > limit {
			return ip, fmt.Errorf("segments can reach %d bytes, cap is %d", ip.top, limit)
		}
	}
	return ip, nil
}

func (p *Plan) Describe() string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d items, packet sizes %d..%d bytes", len(p.items), p.lo, p.hi)
	if p.async {
		fmt.Fprintf(&b, ", delays %s..%s", p.dlo, p.dhi)
	}
	if p.resetMax > 0 {
		fmt.Fprintf(&b, ", re-sent every %s..%s per peer", p.resetMin, p.resetMax)
	} else {
		b.WriteString(", sent once per peer")
	}
	return b.String()
}
