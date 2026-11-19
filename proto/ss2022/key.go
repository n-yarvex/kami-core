package ss2022

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/n-yarvex/kami-core/proto/ss2022/internal/blake3"
)

const (
	ctxSession  = "shadowsocks 2022 session subkey"
	ctxIdentity = "shadowsocks 2022 identity subkey"

	maxChunk   = 0xFFFF
	maxPadding = 900
	skew       = 30 * time.Second

	kindRequest  = 0
	kindResponse = 1
)

type suite struct {
	name   string
	keyLen int
	chacha bool
}

var suites = map[string]*suite{
	"2022-blake3-aes-128-gcm":       {"2022-blake3-aes-128-gcm", 16, false},
	"2022-blake3-aes-256-gcm":       {"2022-blake3-aes-256-gcm", 32, false},
	"2022-blake3-chacha20-poly1305": {"2022-blake3-chacha20-poly1305", 32, true},
}

func suiteFor(name string) (*suite, error) {
	if s, ok := suites[name]; ok {
		return s, nil
	}
	return nil, fmt.Errorf("ss2022: method %q is not supported", name)
}

func (s *suite) parseKey(text string) ([]byte, error) {
	raw, err := base64.StdEncoding.DecodeString(text)
	if err != nil {
		return nil, errors.New("ss2022: password is not valid base64")
	}
	if len(raw) != s.keyLen {
		return nil, fmt.Errorf("ss2022: %s needs a %d-byte key, password decodes to %d bytes", s.name, s.keyLen, len(raw))
	}
	return raw, nil
}

func (s *suite) seal(key []byte) cipher.AEAD {
	if s.chacha {
		a, _ := chacha20poly1305.New(key)
		return a
	}
	blk, _ := aes.NewCipher(key)
	a, _ := cipher.NewGCM(blk)
	return a
}

func derive(context string, key, salt []byte) []byte {
	out := make([]byte, len(key))
	blake3.DeriveKey(out, context, key, salt)
	return out
}

func fingerprint(key []byte) (fp [16]byte) {
	blake3.Sum(fp[:], key)
	return
}

func ecbSeal(key []byte, block *[16]byte) {
	c, _ := aes.NewCipher(key)
	c.Encrypt(block[:], block[:])
}

func ecbOpen(key []byte, block *[16]byte) {
	c, _ := aes.NewCipher(key)
	c.Decrypt(block[:], block[:])
}

func fresh(now time.Time, stamp int64) bool {
	d := now.Unix() - stamp
	return d >= -int64(skew/time.Second) && d <= int64(skew/time.Second)
}

type counter [12]byte

func (c *counter) take() []byte {
	n := make([]byte, 12)
	copy(n, c[:])
	for i := range c {
		c[i]++
		if c[i] != 0 {
			break
		}
	}
	return n
}
