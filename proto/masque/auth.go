package masque

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"strings"
)

type secret struct {
	name string
	sum  [32]byte
}

type accounts struct {
	list []secret
}

func canonical(header string) (string, bool) {
	scheme, rest, ok := strings.Cut(strings.TrimSpace(header), " ")
	if !ok {
		return "", false
	}
	rest = strings.TrimSpace(rest)
	switch strings.ToLower(scheme) {
	case "basic":
		return "basic " + rest, rest != ""
	case "bearer":
		return "bearer " + rest, rest != ""
	}
	return "", false
}

func basicValue(user, password string) string {
	return "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
}

func bearerValue(token string) string { return "Bearer " + token }

func (a *accounts) add(name, header string) {
	c, _ := canonical(header)
	a.list = append(a.list, secret{name: name, sum: sha256.Sum256([]byte(c))})
}

func (a *accounts) check(header string) (string, bool) {
	c, ok := canonical(header)
	sum := sha256.Sum256([]byte(c))
	name, hit := "", 0
	for i := range a.list {
		if subtle.ConstantTimeCompare(sum[:], a.list[i].sum[:]) == 1 {
			name, hit = a.list[i].name, 1
		}
	}
	return name, ok && hit == 1
}
