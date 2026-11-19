package klog

import (
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"time"
)

type Options struct {
	Level     string `json:"level,omitempty"`
	File      string `json:"file,omitempty"`
	Format    string `json:"format,omitempty"`
	Timestamp *bool  `json:"timestamp,omitempty"`
}

const (
	LevelTrace = slog.Level(-8)
	LevelOff   = slog.Level(64)
)

func ParseLevel(s string) (slog.Level, error) {
	switch strings.ToLower(s) {
	case "trace":
		return LevelTrace, nil
	case "debug":
		return slog.LevelDebug, nil
	case "", "info":
		return slog.LevelInfo, nil
	case "warn", "warning":
		return slog.LevelWarn, nil
	case "error":
		return slog.LevelError, nil
	case "off", "none":
		return LevelOff, nil
	}
	return 0, fmt.Errorf("log: unknown level %q", s)
}

func New(o Options, stderr io.Writer) (*slog.Logger, io.Closer, error) {
	level, err := ParseLevel(o.Level)
	if err != nil {
		return nil, nil, err
	}
	var out io.Writer = stderr
	var closer io.Closer = nopCloser{}
	if o.File != "" {
		f, err := os.OpenFile(o.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
		if err != nil {
			return nil, nil, fmt.Errorf("log: %w", err)
		}
		out, closer = f, f
	}
	stamp := o.Timestamp == nil || *o.Timestamp
	opts := &slog.HandlerOptions{
		Level: level,
		ReplaceAttr: func(_ []string, a slog.Attr) slog.Attr {
			switch a.Key {
			case slog.TimeKey:
				if !stamp {
					return slog.Attr{}
				}
				a.Value = slog.StringValue(a.Value.Time().Format(time.DateTime))
			case slog.LevelKey:
				if l, ok := a.Value.Any().(slog.Level); ok && l == LevelTrace {
					a.Value = slog.StringValue("TRACE")
				}
			}
			return a
		},
	}
	switch o.Format {
	case "", "text":
		return slog.New(slog.NewTextHandler(out, opts)), closer, nil
	case "json":
		return slog.New(slog.NewJSONHandler(out, opts)), closer, nil
	}
	return nil, nil, fmt.Errorf("log: unknown format %q", o.Format)
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

func Discard() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: LevelOff}))
}
