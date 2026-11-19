package juicity

import (
	"crypto/subtle"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"strings"
)

const authLen = 2 + 16 + 32

type credential struct {
	name     string
	id       [16]byte
	password string
}

func parseUUID(s string) ([16]byte, error) {
	var id [16]byte
	h := strings.ReplaceAll(s, "-", "")
	raw, err := hex.DecodeString(h)
	if err != nil || len(raw) != 16 || len(s) != 36 {
		return id, fmt.Errorf("juicity: %q is not a uuid", s)
	}
	copy(id[:], raw)
	return id, nil
}

func tokenFor(cs *tls.ConnectionState, id [16]byte, password string) ([32]byte, error) {
	var out [32]byte
	km, err := cs.ExportKeyingMaterial(string(id[:]), []byte(password), len(out))
	if err != nil {
		return out, err
	}
	copy(out[:], km)
	return out, nil
}

func authFrame(cs *tls.ConnectionState, c credential) ([]byte, error) {
	tok, err := tokenFor(cs, c.id, c.password)
	if err != nil {
		return nil, err
	}
	frame := make([]byte, 0, authLen)
	frame = append(frame, 0, 0)
	frame = append(frame, c.id[:]...)
	return append(frame, tok[:]...), nil
}

type roster struct {
	byID map[[16]byte]credential
}

func newRoster(list []credential) *roster {
	r := &roster{byID: make(map[[16]byte]credential, len(list))}
	for _, c := range list {
		r.byID[c.id] = c
	}
	return r
}

func (r *roster) verify(cs *tls.ConnectionState, frame []byte) (string, bool) {
	if len(frame) != authLen || frame[0] != 0 || frame[1] != 0 {
		return "", false
	}
	var id [16]byte
	copy(id[:], frame[2:18])
	cred, known := r.byID[id]
	want, err := tokenFor(cs, id, cred.password)
	if err != nil {
		return "", false
	}
	ok := subtle.ConstantTimeCompare(want[:], frame[18:]) == 1
	return cred.name, ok && known
}
