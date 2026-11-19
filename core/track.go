package core

import (
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

type flow struct {
	id       uint64
	Inbound  string    `json:"inbound"`
	User     string    `json:"user,omitempty"`
	Network  string    `json:"network"`
	Source   string    `json:"source"`
	Dest     string    `json:"dest"`
	Protocol string    `json:"protocol,omitempty"`
	Outbound string    `json:"outbound"`
	Started  time.Time `json:"started"`
	up, down atomic.Int64
	cancel   func()
}

type FlowInfo struct {
	ID       uint64    `json:"id"`
	Inbound  string    `json:"inbound"`
	User     string    `json:"user,omitempty"`
	Network  string    `json:"network"`
	Source   string    `json:"source"`
	Dest     string    `json:"dest"`
	Protocol string    `json:"protocol,omitempty"`
	Outbound string    `json:"outbound"`
	Started  time.Time `json:"started"`
	Up       int64     `json:"up"`
	Down     int64     `json:"down"`
}

type tracker struct {
	mu    sync.Mutex
	next  uint64
	flows map[uint64]*flow
	up    atomic.Int64
	down  atomic.Int64
	total atomic.Uint64
}

func newTracker() *tracker { return &tracker{flows: map[uint64]*flow{}} }

func (t *tracker) add(f *flow) {
	t.mu.Lock()
	t.next++
	f.id = t.next
	t.flows[f.id] = f
	t.mu.Unlock()
	t.total.Add(1)
}

func (t *tracker) drop(f *flow) {
	t.mu.Lock()
	delete(t.flows, f.id)
	t.mu.Unlock()
}

func (f *flow) addUp(n int64)   { f.up.Add(n) }
func (f *flow) addDown(n int64) { f.down.Add(n) }

func (t *tracker) list() []FlowInfo {
	t.mu.Lock()
	out := make([]FlowInfo, 0, len(t.flows))
	for _, f := range t.flows {
		out = append(out, FlowInfo{
			ID: f.id, Inbound: f.Inbound, User: f.User, Network: f.Network,
			Source: f.Source, Dest: f.Dest, Protocol: f.Protocol, Outbound: f.Outbound,
			Started: f.Started, Up: f.up.Load(), Down: f.down.Load(),
		})
	}
	t.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

func (t *tracker) kill(id uint64) bool {
	t.mu.Lock()
	f, ok := t.flows[id]
	t.mu.Unlock()
	if ok {
		f.cancel()
	}
	return ok
}

func (t *tracker) killAll() {
	t.mu.Lock()
	all := make([]*flow, 0, len(t.flows))
	for _, f := range t.flows {
		all = append(all, f)
	}
	t.mu.Unlock()
	for _, f := range all {
		f.cancel()
	}
}
