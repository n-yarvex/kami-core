package adapter

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/addr"
)

type Metadata struct {
	Inbound     string
	InboundType string
	User        string
	Network     string
	Source      addr.Addr
	Dest        addr.Addr
	Domain      string
	Protocol    string
	OnConnect   func(err error)
}

func (m Metadata) Target() addr.Addr {
	if m.Domain != "" {
		return addr.FromDomain(m.Domain, m.Dest.Port())
	}
	return m.Dest
}

type PacketConn interface {
	ReadPacket(p []byte) (int, addr.Addr, error)
	WritePacket(p []byte, peer addr.Addr) error
	SetReadDeadline(t time.Time) error
	Close() error
}

type Router interface {
	Stream(ctx context.Context, conn net.Conn, md Metadata)
	Packet(ctx context.Context, pc PacketConn, md Metadata)
}

type Resolver interface {
	Lookup(ctx context.Context, host string) ([]netip.Addr, error)
}

type Dialer interface {
	DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error)
	ListenPacket(ctx context.Context) (net.PacketConn, error)
}

type Inbound interface {
	Tag() string
	Type() string
	Start() error
	Close() error
}

type Outbound interface {
	Tag() string
	Type() string
	DialStream(ctx context.Context, dest addr.Addr) (net.Conn, error)
	OpenPacket(ctx context.Context, dest addr.Addr) (PacketConn, error)
	Close() error
}

type Starter interface {
	Start() error
}

type NetworkChecker interface {
	SupportsUDP() bool
}

type InboundEnv struct {
	Ctx       context.Context
	Tag       string
	Log       *slog.Logger
	Router    Router
	Resolver  Resolver
	Listen    addr.Addr
	ListenTCP func() (net.Listener, error)
	ListenUDP func() (net.PacketConn, error)
}

type OutboundEnv struct {
	Tag      string
	Log      *slog.Logger
	Dialer   Dialer
	Resolver Resolver
	Lookup   func(tag string) (Outbound, bool)
}

type InboundFactory func(env *InboundEnv, raw json.RawMessage) (Inbound, error)
type OutboundFactory func(env *OutboundEnv, raw json.RawMessage) (Outbound, error)

var (
	regMu     sync.RWMutex
	inbounds  = map[string]InboundFactory{}
	outbounds = map[string]OutboundFactory{}
)

func RegisterInbound(typ string, f InboundFactory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := inbounds[typ]; dup {
		panic("adapter: inbound " + typ + " registered twice")
	}
	inbounds[typ] = f
}

func RegisterOutbound(typ string, f OutboundFactory) {
	regMu.Lock()
	defer regMu.Unlock()
	if _, dup := outbounds[typ]; dup {
		panic("adapter: outbound " + typ + " registered twice")
	}
	outbounds[typ] = f
}

func InboundFor(typ string) (InboundFactory, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	if f, ok := inbounds[typ]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("unknown inbound type %q (known: %v)", typ, keys(inbounds))
}

func OutboundFor(typ string) (OutboundFactory, error) {
	regMu.RLock()
	defer regMu.RUnlock()
	if f, ok := outbounds[typ]; ok {
		return f, nil
	}
	return nil, fmt.Errorf("unknown outbound type %q (known: %v)", typ, keys(outbounds))
}

func keys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func Decode(raw json.RawMessage, into any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	dec := json.NewDecoder(bytesReader(raw))
	dec.DisallowUnknownFields()
	return dec.Decode(into)
}
