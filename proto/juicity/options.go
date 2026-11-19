package juicity

import (
	"crypto/tls"
	"errors"
	"fmt"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/proto/juicity/noise"
)

const (
	defaultIdle      = 30 * time.Second
	defaultKeepAlive = 10 * time.Second
	defaultWindowMiB = 8
	defaultConnMiB   = 20
	authDeadline     = 10 * time.Second
	headerWait       = 100 * time.Millisecond
	clientNAT        = 3 * time.Minute
	serverNAT        = 4 * time.Minute
	minServerStreams = 30
)

type transportOptions struct {
	IdleTimeout  config.Duration `json:"idle_timeout"`
	KeepAlive    config.Duration `json:"keepalive"`
	StreamWindow int             `json:"stream_window_mib"`
	ConnWindow   int             `json:"conn_window_mib"`
	Noise        *noise.Config   `json:"noise"`
}

func (t transportOptions) quicConfig(maxStreams int64) (*quic.Config, error) {
	idle, ka := t.IdleTimeout.Std(), t.KeepAlive.Std()
	if idle == 0 {
		idle = defaultIdle
	}
	if ka == 0 {
		ka = defaultKeepAlive
	}
	if idle < 0 || ka < 0 || ka >= idle {
		return nil, errors.New("juicity: keepalive must be positive and shorter than idle_timeout")
	}
	sw, cw := t.StreamWindow, t.ConnWindow
	if sw == 0 {
		sw = defaultWindowMiB
	}
	if cw == 0 {
		cw = defaultConnMiB
	}
	if sw < 1 || cw < sw {
		return nil, errors.New("juicity: stream_window_mib must be >= 1 and conn_window_mib >= stream_window_mib")
	}
	return &quic.Config{
		MaxIdleTimeout:                 idle,
		KeepAlivePeriod:                ka,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIncomingStreams:             maxStreams,
		MaxIncomingUniStreams:          8,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         uint64(sw) << 20,
		InitialConnectionReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow:     uint64(cw) << 20,
	}, nil
}

func (t transportOptions) plan() (*noise.Plan, error) {
	if t.Noise == nil {
		return nil, nil
	}
	p, err := t.Noise.Compile()
	if err != nil {
		return nil, fmt.Errorf("juicity: %w", err)
	}
	return p, nil
}

func forceH3(c *tls.Config) *tls.Config {
	c = c.Clone()
	c.NextProtos = []string{"h3"}
	c.MinVersion = tls.VersionTLS13
	return c
}
