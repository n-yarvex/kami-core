package masque

import (
	"crypto/tls"
	"errors"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/n-yarvex/kami-core/config"
)

const (
	defaultIdle      = 30 * time.Second
	defaultKeepAlive = 10 * time.Second
	defaultWindowMiB = 8
	defaultConnMiB   = 20
	probeWait        = 100 * time.Millisecond
	settingsWait     = 10 * time.Second
	flowNAT          = 3 * time.Minute
	maxFlowTargets   = 64
	DefaultTemplate  = "/.well-known/masque/udp/{target_host}/{target_port}/"
)

type transportOptions struct {
	IdleTimeout  config.Duration `json:"idle_timeout"`
	KeepAlive    config.Duration `json:"keepalive"`
	StreamWindow int             `json:"stream_window_mib"`
	ConnWindow   int             `json:"conn_window_mib"`
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
		return nil, errors.New("masque: keepalive must be positive and shorter than idle_timeout")
	}
	sw, cw := t.StreamWindow, t.ConnWindow
	if sw == 0 {
		sw = defaultWindowMiB
	}
	if cw == 0 {
		cw = defaultConnMiB
	}
	if sw < 1 || cw < sw {
		return nil, errors.New("masque: stream_window_mib must be >= 1 and conn_window_mib >= stream_window_mib")
	}
	return &quic.Config{
		MaxIdleTimeout:                 idle,
		KeepAlivePeriod:                ka,
		HandshakeIdleTimeout:           10 * time.Second,
		MaxIncomingStreams:             maxStreams,
		MaxIncomingUniStreams:          16,
		EnableDatagrams:                true,
		InitialStreamReceiveWindow:     1 << 20,
		MaxStreamReceiveWindow:         uint64(sw) << 20,
		InitialConnectionReceiveWindow: 2 << 20,
		MaxConnectionReceiveWindow:     uint64(cw) << 20,
	}, nil
}

func forceH3(c *tls.Config) *tls.Config {
	c = c.Clone()
	c.NextProtos = []string{"h3"}
	c.MinVersion = tls.VersionTLS13
	return c
}
