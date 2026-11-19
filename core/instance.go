package core

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"slices"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/dialer"
	"github.com/n-yarvex/kami-core/dns"
	"github.com/n-yarvex/kami-core/route"
)

var localTypes = []string{"socks", "http", "mixed"}

var groupTypes = []string{"selector", "urltest", "fallback"}

type Instance struct {
	cfg      *config.Config
	log      *slog.Logger
	logClose io.Closer

	ctx    context.Context
	cancel context.CancelFunc

	resolver  *dns.Resolver
	engine    *route.Engine
	outbounds map[string]adapter.Outbound
	order     []string
	inbounds  []adapter.Inbound
	policy    map[string]inboundPolicy
	tracker   *tracker
	api       *apiServer
	reload    func() error

	started time.Time
	mu      sync.Mutex
	closed  bool
}

type outboundSpec struct {
	common config.OutboundCommon
	rest   json.RawMessage
}

func New(cfg *config.Config, log *slog.Logger) (*Instance, error) {
	ctx, cancel := context.WithCancel(context.Background())
	in := &Instance{
		cfg:       cfg,
		log:       log,
		ctx:       ctx,
		cancel:    cancel,
		outbounds: map[string]adapter.Outbound{},
		policy:    map[string]inboundPolicy{},
		tracker:   newTracker(),
	}
	if err := in.build(); err != nil {
		in.release()
		return nil, err
	}
	return in, nil
}

func (in *Instance) SetLogCloser(c io.Closer) { in.logClose = c }

func (in *Instance) build() error {
	cfg := in.cfg
	sets, err := route.LoadSets(cfg.Route.RuleSets)
	if err != nil {
		return err
	}
	specs, err := in.specs()
	if err != nil {
		return err
	}
	order, err := buildOrder(specs)
	if err != nil {
		return err
	}
	if err := checkGroups(specs); err != nil {
		return err
	}

	in.resolver, err = dns.New(cfg.DNS, dns.Deps{
		Log:      in.log,
		RuleSets: sets,
		DialFor:  in.dnsDialer,
	})
	if err != nil {
		return err
	}

	for _, tag := range order {
		sp := specs[tag]
		ob, err := in.buildOutbound(sp)
		if err != nil {
			return fmt.Errorf("outbound %q: %w", tag, err)
		}
		in.outbounds[tag] = ob
		in.order = append(in.order, tag)
	}

	fallback := ""
	if len(in.order) > 0 {
		fallback = in.order[0]
		if len(cfg.Outbounds) > 0 {
			var first config.OutboundCommon
			config.Split(cfg.Outbounds[0], &first)
			fallback = first.Tag
		}
	}
	in.engine, err = route.Compile(cfg.Route, sets, fallback)
	if err != nil {
		return err
	}

	r := &router{in: in}
	for i, raw := range cfg.Inbounds {
		var ic config.InboundCommon
		rest, err := config.Split(raw, &ic)
		if err != nil {
			return fmt.Errorf("inbounds[%d]: %w", i, err)
		}
		ib, err := in.buildInbound(r, ic, rest)
		if err != nil {
			return fmt.Errorf("inbound %q: %w", ic.Tag, err)
		}
		in.inbounds = append(in.inbounds, ib)
	}
	if cfg.API != nil {
		in.api, err = newAPI(in, *cfg.API)
		if err != nil {
			return err
		}
	}
	return nil
}

func (in *Instance) specs() (map[string]outboundSpec, error) {
	specs := map[string]outboundSpec{}
	list := in.cfg.Outbounds
	if len(list) == 0 {
		list = []json.RawMessage{json.RawMessage(`{"type":"direct","tag":"direct"}`)}
		in.cfg.Outbounds = list
	}
	for i, raw := range list {
		var oc config.OutboundCommon
		rest, err := config.Split(raw, &oc)
		if err != nil {
			return nil, fmt.Errorf("outbounds[%d]: %w", i, err)
		}
		specs[oc.Tag] = outboundSpec{common: oc, rest: rest}
	}
	return specs, nil
}

func buildOrder(specs map[string]outboundSpec) ([]string, error) {
	tags := make([]string, 0, len(specs))
	for t := range specs {
		tags = append(tags, t)
	}
	slices.Sort(tags)
	var order []string
	state := map[string]int{}
	var visit func(tag string, path []string) error
	visit = func(tag string, path []string) error {
		switch state[tag] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("detour loop: %v -> %s", path, tag)
		}
		state[tag] = 1
		if d := specs[tag].common.Detour; d != "" {
			if _, ok := specs[d]; !ok {
				return fmt.Errorf("outbound %q: detour %q does not exist", tag, d)
			}
			if err := visit(d, append(path, tag)); err != nil {
				return err
			}
		}
		state[tag] = 2
		order = append(order, tag)
		return nil
	}
	for _, t := range tags {
		if err := visit(t, nil); err != nil {
			return nil, err
		}
	}
	return order, nil
}

func checkGroups(specs map[string]outboundSpec) error {
	edges := map[string][]string{}
	for tag, sp := range specs {
		if !slices.Contains(groupTypes, sp.common.Type) {
			continue
		}
		var g struct {
			Outbounds []string `json:"outbounds"`
		}
		json.Unmarshal(sp.rest, &g)
		for _, m := range g.Outbounds {
			if _, ok := specs[m]; !ok {
				return fmt.Errorf("group %q: member %q does not exist", tag, m)
			}
		}
		edges[tag] = g.Outbounds
	}
	state := map[string]int{}
	var visit func(string) error
	visit = func(t string) error {
		switch state[t] {
		case 2:
			return nil
		case 1:
			return fmt.Errorf("group membership loop through %q", t)
		}
		state[t] = 1
		for _, m := range edges[t] {
			if err := visit(m); err != nil {
				return err
			}
		}
		state[t] = 2
		return nil
	}
	for t := range edges {
		if err := visit(t); err != nil {
			return err
		}
	}
	return nil
}

func (in *Instance) dnsDialer(detour string) (dns.DialFunc, error) {
	if detour == "" {
		d := dialer.New(dialer.Options{}, nil, nil)
		return d.DialStream, nil
	}
	return func(ctx context.Context, dest addr.Addr) (net.Conn, error) {
		ob, ok := in.outbounds[detour]
		if !ok {
			return nil, fmt.Errorf("dns detour %q is not available", detour)
		}
		return ob.DialStream(ctx, dest)
	}, nil
}

func (in *Instance) buildOutbound(sp outboundSpec) (adapter.Outbound, error) {
	factory, err := adapter.OutboundFor(sp.common.Type)
	if err != nil {
		return nil, err
	}
	var detour adapter.Outbound
	if sp.common.Detour != "" {
		detour = in.outbounds[sp.common.Detour]
	}
	d := dialer.New(dialer.Options{
		BindInterface:  sp.common.BindInterface,
		RoutingMark:    sp.common.RoutingMark,
		ConnectTimeout: sp.common.ConnectTimeout.Std(),
		Strategy:       sp.common.DomainStrategy,
	}, in.resolver, detour)
	env := &adapter.OutboundEnv{
		Tag:      sp.common.Tag,
		Log:      in.log.With("outbound", sp.common.Tag),
		Dialer:   d,
		Resolver: in.resolver,
		Lookup: func(tag string) (adapter.Outbound, bool) {
			ob, ok := in.outbounds[tag]
			return ob, ok
		},
	}
	return factory(env, sp.rest)
}

func (in *Instance) buildInbound(r *router, ic config.InboundCommon, rest json.RawMessage) (adapter.Inbound, error) {
	factory, err := adapter.InboundFor(ic.Type)
	if err != nil {
		return nil, err
	}
	if ic.Listen == "" {
		return nil, errors.New("listen is required")
	}
	listen, _ := addr.Parse(ic.Listen)
	local := slices.Contains(localTypes, ic.Type)
	allow := local
	if ic.AllowPrivate != nil {
		allow = *ic.AllowPrivate
	}
	in.policy[ic.Tag] = inboundPolicy{sniff: ic.Sniff, allowPrivate: allow}
	env := &adapter.InboundEnv{
		Ctx:      in.ctx,
		Tag:      ic.Tag,
		Log:      in.log.With("inbound", ic.Tag),
		Router:   r,
		Resolver: in.resolver,
		Listen:   listen,
		ListenTCP: func() (net.Listener, error) {
			var lc net.ListenConfig
			return lc.Listen(in.ctx, "tcp", ic.Listen)
		},
		ListenUDP: func() (net.PacketConn, error) {
			var lc net.ListenConfig
			return lc.ListenPacket(in.ctx, "udp", ic.Listen)
		},
	}
	return factory(env, rest)
}

func (in *Instance) Start() error {
	in.started = time.Now()
	for _, tag := range in.order {
		if s, ok := in.outbounds[tag].(adapter.Starter); ok {
			if err := s.Start(); err != nil {
				return fmt.Errorf("outbound %q: %w", tag, err)
			}
		}
	}
	for _, ib := range in.inbounds {
		if err := ib.Start(); err != nil {
			return fmt.Errorf("inbound %q: %w", ib.Tag(), err)
		}
		in.log.Info("inbound listening", "tag", ib.Tag(), "type", ib.Type())
	}
	if in.api != nil {
		if err := in.api.start(); err != nil {
			return err
		}
	}
	return nil
}

func (in *Instance) Close() error {
	in.release()
	if in.logClose != nil {
		in.logClose.Close()
	}
	return nil
}

func (in *Instance) release() {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return
	}
	in.closed = true
	in.mu.Unlock()
	if in.api != nil {
		in.api.close()
	}
	for _, ib := range in.inbounds {
		ib.Close()
	}
	in.cancel()
	in.tracker.killAll()
	for i := len(in.order) - 1; i >= 0; i-- {
		in.outbounds[in.order[i]].Close()
	}
}
