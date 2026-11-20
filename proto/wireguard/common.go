package wireguard

import (
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"golang.zx2c4.com/wireguard/device"
)

const defaultMTU = 1420

func hexKey(label, b64 string) (string, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil || len(raw) != 32 {
		return "", fmt.Errorf("wireguard: %s must be a base64 encoded 32 byte key", label)
	}
	return hex.EncodeToString(raw), nil
}

func parsePrefixes(label string, list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		if p, err := netip.ParsePrefix(s); err == nil {
			out = append(out, p)
			continue
		}
		a, err := netip.ParseAddr(s)
		if err != nil {
			return nil, fmt.Errorf("wireguard: bad %s entry %q", label, s)
		}
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func checkMTU(mtu int) (int, error) {
	if mtu == 0 {
		return defaultMTU, nil
	}
	if mtu < 576 || mtu > 9000 {
		return 0, errors.New("wireguard: mtu must be between 576 and 9000")
	}
	return mtu, nil
}

func checkReserved(r []int) (*[3]byte, error) {
	if len(r) == 0 {
		return nil, nil
	}
	if len(r) != 3 {
		return nil, errors.New("wireguard: reserved must have exactly 3 numbers")
	}
	var out [3]byte
	for i, v := range r {
		if v < 0 || v > 255 {
			return nil, errors.New("wireguard: reserved numbers must be 0-255")
		}
		out[i] = byte(v)
	}
	return &out, nil
}

func deviceLogger(log *slog.Logger, tag string) *device.Logger {
	return &device.Logger{
		Verbosef: func(format string, args ...any) {
			log.Debug(fmt.Sprintf("wireguard %s: "+format, append([]any{tag}, args...)...))
		},
		Errorf: func(format string, args ...any) {
			log.Warn(fmt.Sprintf("wireguard %s: "+format, append([]any{tag}, args...)...))
		},
	}
}
