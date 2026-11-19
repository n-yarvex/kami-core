package sniff

import (
	"bytes"
	"encoding/binary"
	"net"
	"strings"
	"time"
)

type Result struct {
	Protocol string
	Domain   string
}

const peekSize = 4096

func Stream(conn net.Conn, wait time.Duration) ([]byte, Result) {
	buf := make([]byte, peekSize)
	conn.SetReadDeadline(time.Now().Add(wait))
	n, _ := conn.Read(buf)
	buf = buf[:n]
	if n > 0 && buf[0] == 0x16 && n >= 5 {
		need := 5 + int(binary.BigEndian.Uint16(buf[3:5]))
		for len(buf) < need && need <= peekSize {
			more, err := conn.Read(buf[len(buf):need])
			buf = buf[:len(buf)+more]
			if err != nil {
				break
			}
		}
	}
	conn.SetReadDeadline(time.Time{})
	return buf, Identify(buf)
}

func Identify(b []byte) Result {
	if host, ok := tlsServerName(b); ok {
		return Result{"tls", host}
	}
	if host, ok := httpHost(b); ok {
		return Result{"http", host}
	}
	return Result{}
}

type reader struct {
	b   []byte
	bad bool
}

func (r *reader) take(n int) []byte {
	if r.bad || n < 0 || len(r.b) < n {
		r.bad = true
		return nil
	}
	out := r.b[:n]
	r.b = r.b[n:]
	return out
}

func (r *reader) u8() int {
	if v := r.take(1); v != nil {
		return int(v[0])
	}
	return 0
}

func (r *reader) u16() int {
	if v := r.take(2); v != nil {
		return int(binary.BigEndian.Uint16(v))
	}
	return 0
}

func tlsServerName(b []byte) (string, bool) {
	if len(b) < 5 || b[0] != 0x16 || b[1] != 3 {
		return "", false
	}
	rec := &reader{b: b[5:]}
	if end := int(binary.BigEndian.Uint16(b[3:5])); end < len(rec.b) {
		rec.b = rec.b[:end]
	}
	if rec.u8() != 1 {
		return "", false
	}
	length := int(rec.u8())<<16 | rec.u16()
	body := &reader{b: rec.take(length)}
	if rec.bad {
		body = &reader{b: rec.b}
	}
	body.take(2 + 32)
	body.take(body.u8())
	body.take(body.u16())
	body.take(body.u8())
	exts := &reader{b: body.take(body.u16())}
	for !exts.bad && len(exts.b) >= 4 {
		kind := exts.u16()
		data := &reader{b: exts.take(exts.u16())}
		if kind != 0 || data.bad {
			continue
		}
		list := &reader{b: data.take(data.u16())}
		for !list.bad && len(list.b) >= 3 {
			nameType := list.u8()
			name := list.take(list.u16())
			if nameType == 0 && name != nil {
				host := strings.ToLower(string(name))
				if validHost(host) {
					return host, true
				}
			}
		}
	}
	return "", false
}

var methods = [][]byte{[]byte("GET "), []byte("POST "), []byte("HEAD "), []byte("PUT "), []byte("DELETE "), []byte("OPTIONS "), []byte("PATCH "), []byte("TRACE ")}

func httpHost(b []byte) (string, bool) {
	ok := false
	for _, m := range methods {
		if bytes.HasPrefix(b, m) {
			ok = true
			break
		}
	}
	if !ok {
		return "", false
	}
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if len(line) > 5 && bytes.EqualFold(line[:5], []byte("host:")) {
			host := strings.ToLower(strings.TrimSpace(string(line[5:])))
			if strings.HasPrefix(host, "[") {
				if i := strings.IndexByte(host, ']'); i > 0 {
					host = host[1:i]
				}
			} else if i := strings.LastIndexByte(host, ':'); i > 0 {
				host = host[:i]
			}
			if validHost(host) {
				return host, true
			}
			return "", false
		}
	}
	return "", false
}

func validHost(h string) bool {
	if h == "" || len(h) > 253 {
		return false
	}
	for i := 0; i < len(h); i++ {
		c := h[i]
		switch {
		case c >= 'a' && c <= 'z', c >= '0' && c <= '9', c == '-', c == '.', c == '_', c == ':':
		default:
			return false
		}
	}
	return true
}
