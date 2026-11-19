package nakis

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/tlsx"
)

func init() {
	adapter.RegisterInbound("nakis", newInbound)
}

type inboundOptions struct {
	Users            []userOption    `json:"users"`
	UUID             string          `json:"uuid"`
	TLS              tlsx.Server     `json:"tls"`
	HandshakeTimeout config.Duration `json:"handshake_timeout"`
	IdleTimeout      config.Duration `json:"idle_timeout"`
	HalfCloseTimeout config.Duration `json:"half_close_timeout"`
	MergePack        int             `json:"merge_pack"`
	MaxQueue         int             `json:"max_queue"`
	SendPack         int             `json:"send_pack"`
	SendTail         int             `json:"send_tail"`
	SendQuiet        int             `json:"send_quiet"`
	DisableUDP       bool            `json:"disable_udp"`
	UDPIdleTimeout   config.Duration `json:"udp_idle_timeout"`
	UDPJitter        config.Duration `json:"udp_jitter"`
}

type userOption struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type inbound struct {
	env     *adapter.InboundEnv
	svc     *Service
	tlsConf *tls.Config

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("nakis: %w", err)
	}
	users := make([]User, 0, len(o.Users)+1)
	for i, u := range o.Users {
		name := u.Name
		if name == "" {
			name = fmt.Sprintf("user%d", i+1)
		}
		users = append(users, User{Name: name, UUID: u.UUID})
	}
	if o.UUID != "" {
		users = append(users, User{Name: "default", UUID: o.UUID})
	}
	if len(users) == 0 {
		return nil, errors.New("nakis: users or uuid is required")
	}
	if len(o.TLS.ALPN) == 0 {
		o.TLS.ALPN = []string{"http/1.1"}
	}
	cfg, err := o.TLS.Config()
	if err != nil {
		return nil, fmt.Errorf("nakis: %w", err)
	}
	svc, err := NewService(ServiceOptions{
		Log:    env.Log,
		Router: env.Router,
		Tag:    env.Tag,
		Users:  users,
		Handshake: func(ctx context.Context, conn net.Conn) (net.Conn, error) {
			tc := tls.Server(conn, cfg)
			if err := tc.HandshakeContext(ctx); err != nil {
				return nil, err
			}
			return tc, nil
		},
		HandshakeTimeout: o.HandshakeTimeout.Std(),
		IdleTimeout:      o.IdleTimeout.Std(),
		HalfCloseTimeout: o.HalfCloseTimeout.Std(),
		SendPack:         o.SendPack,
		SendTail:         o.SendTail,
		SendQuiet:        o.SendQuiet,
		MergePack:        o.MergePack,
		MaxQueue:         o.MaxQueue,
		DisableUDP:       o.DisableUDP,
		UDPIdleTimeout:   o.UDPIdleTimeout.Std(),
		UDPJitter:        o.UDPJitter.Std(),
	})
	if err != nil {
		return nil, err
	}
	return &inbound{env: env, svc: svc, tlsConf: cfg}, nil
}

func (i *inbound) Tag() string  { return i.env.Tag }
func (i *inbound) Type() string { return "nakis" }

func (i *inbound) Start() error {
	ln, err := i.env.ListenTCP()
	if err != nil {
		return err
	}
	i.mu.Lock()
	i.ln = ln
	i.mu.Unlock()
	i.wg.Add(1)
	go i.accept(ln)
	return nil
}

func (i *inbound) accept(ln net.Listener) {
	defer i.wg.Done()
	var pause time.Duration
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			pause = min(max(pause*2, 5*time.Millisecond), time.Second)
			time.Sleep(pause)
			continue
		}
		pause = 0
		i.wg.Add(1)
		go func() {
			defer i.wg.Done()
			src := addr.FromNet(conn.RemoteAddr())
			if err := i.svc.NewConnection(i.env.Ctx, conn, src); err != nil {
				i.env.Log.Debug("nakis connection rejected", "from", src.String(), "err", err)
				conn.Close()
			}
		}()
	}
}

func (i *inbound) Close() error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	ln := i.ln
	i.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	i.svc.Close()
	i.wg.Wait()
	return nil
}
