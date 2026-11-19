package juicity

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"

	"github.com/quic-go/quic-go"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/proto/juicity/noise"
	"github.com/n-yarvex/kami-core/tlsx"
)

const errAuth quic.ApplicationErrorCode = 0x0c

func init() {
	adapter.RegisterInbound("juicity", newInbound)
}

type userOption struct {
	Name     string `json:"name"`
	UUID     string `json:"uuid"`
	Password string `json:"password"`
}

type inboundOptions struct {
	transportOptions
	Users      []userOption    `json:"users"`
	TLS        tlsx.Server     `json:"tls"`
	MaxStreams int             `json:"max_streams"`
	UDPTimeout config.Duration `json:"udp_timeout"`
	DisableUDP bool            `json:"disable_udp"`
}

type inbound struct {
	env    *adapter.InboundEnv
	tls    *tls.Config
	qcfg   *quic.Config
	plan   *noise.Plan
	roster *roster
	nat    time.Duration
	udp    bool

	mu     sync.Mutex
	tr     *quic.Transport
	wire   net.PacketConn
	ln     *quic.Listener
	live   map[*quic.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("juicity: %w", err)
	}
	if len(o.Users) == 0 {
		return nil, errors.New("juicity: users is required")
	}
	var creds []credential
	names := map[string]bool{}
	ids := map[[16]byte]bool{}
	for i, u := range o.Users {
		id, err := parseUUID(u.UUID)
		if err != nil {
			return nil, err
		}
		if u.Password == "" {
			return nil, errors.New("juicity: user password must not be empty")
		}
		if u.Name == "" {
			u.Name = fmt.Sprintf("user%d", i+1)
		}
		if names[u.Name] || ids[id] {
			return nil, fmt.Errorf("juicity: duplicate user %q", u.Name)
		}
		names[u.Name], ids[id] = true, true
		creds = append(creds, credential{name: u.Name, id: id, password: u.Password})
	}
	streams := o.MaxStreams
	if streams == 0 {
		streams = 1024
	}
	if streams < minServerStreams {
		return nil, fmt.Errorf("juicity: max_streams must be at least %d", minServerStreams)
	}
	qcfg, err := o.quicConfig(int64(streams))
	if err != nil {
		return nil, err
	}
	plan, err := o.plan()
	if err != nil {
		return nil, err
	}
	tcfg, err := o.TLS.Config()
	if err != nil {
		return nil, fmt.Errorf("juicity: %w", err)
	}
	in := &inbound{
		env: env, tls: forceH3(tcfg), qcfg: qcfg, plan: plan, roster: newRoster(creds),
		nat: o.UDPTimeout.Std(), udp: !o.DisableUDP, live: map[*quic.Conn]struct{}{},
	}
	if in.nat <= 0 {
		in.nat = serverNAT
	}
	return in, nil
}

func (in *inbound) Tag() string  { return in.env.Tag }
func (in *inbound) Type() string { return "juicity" }

func (in *inbound) Start() error {
	pc, err := in.env.ListenUDP()
	if err != nil {
		return err
	}
	wire := pc
	if in.plan != nil {
		wire = noise.Wrap(pc, in.plan, noise.Server)
		in.env.Log.Info("juicity noise enabled", "inbound", in.env.Tag, "plan", in.plan.Describe())
	}
	tr := &quic.Transport{Conn: wire}
	ln, err := tr.Listen(in.tls, in.qcfg)
	if err != nil {
		tr.Close()
		wire.Close()
		return err
	}
	in.mu.Lock()
	in.tr, in.wire, in.ln = tr, wire, ln
	in.mu.Unlock()
	in.wg.Add(1)
	go in.accept(ln)
	return nil
}

func (in *inbound) accept(ln *quic.Listener) {
	defer in.wg.Done()
	for {
		c, err := ln.Accept(context.Background())
		if err != nil {
			return
		}
		in.mu.Lock()
		if in.closed {
			in.mu.Unlock()
			c.CloseWithError(0, "")
			return
		}
		in.live[c] = struct{}{}
		in.mu.Unlock()
		in.wg.Add(1)
		go func() {
			defer in.wg.Done()
			in.serve(c)
			in.mu.Lock()
			delete(in.live, c)
			in.mu.Unlock()
		}()
	}
}

type authState struct {
	ok   chan struct{}
	user string
}

func (in *inbound) serve(c *quic.Conn) {
	st := &authState{ok: make(chan struct{})}
	go in.authenticate(c, st)
	for {
		s, err := c.AcceptStream(c.Context())
		if err != nil {
			return
		}
		go in.stream(c, s, st)
	}
}

func (in *inbound) authenticate(c *quic.Conn, st *authState) {
	ctx, cancel := context.WithTimeout(c.Context(), authDeadline)
	defer cancel()
	us, err := c.AcceptUniStream(ctx)
	if err != nil {
		c.CloseWithError(errAuth, "")
		return
	}
	us.SetReadDeadline(time.Now().Add(authDeadline))
	var frame [authLen]byte
	if _, err := io.ReadFull(us, frame[:]); err != nil {
		c.CloseWithError(errAuth, "")
		return
	}
	cs := c.ConnectionState().TLS
	name, ok := in.roster.verify(&cs, frame[:])
	if !ok {
		in.env.Log.Debug("juicity auth failed", "from", c.RemoteAddr().String())
		c.CloseWithError(errAuth, "")
		return
	}
	st.user = name
	close(st.ok)
}

func (in *inbound) stream(c *quic.Conn, s *quic.Stream, st *authState) {
	select {
	case <-st.ok:
	case <-c.Context().Done():
		return
	}
	s.SetReadDeadline(time.Now().Add(authDeadline))
	r := bufio.NewReaderSize(s, 4096)
	network, dest, err := readHeader(r)
	if err != nil {
		s.CancelRead(0)
		s.CancelWrite(0)
		return
	}
	s.SetReadDeadline(time.Time{})
	md := adapter.Metadata{
		Inbound:     in.env.Tag,
		InboundType: "juicity",
		User:        st.user,
		Source:      addr.FromNet(c.RemoteAddr()),
	}
	if network == netTCP {
		md.Network, md.Dest = "tcp", dest
		conn := newTCPConn(s, r, c.LocalAddr(), c.RemoteAddr())
		in.env.Router.Stream(in.env.Ctx, conn, md)
		return
	}
	if !in.udp {
		s.CancelRead(0)
		s.CancelWrite(0)
		return
	}
	md.Network = "udp"
	pc := newDatagramConn(s, r, false, in.nat)
	in.env.Router.Packet(in.env.Ctx, pc, md)
	pc.Close()
}

func (in *inbound) Close() error {
	in.mu.Lock()
	if in.closed {
		in.mu.Unlock()
		return nil
	}
	in.closed = true
	conns := make([]*quic.Conn, 0, len(in.live))
	for c := range in.live {
		conns = append(conns, c)
	}
	ln, tr, wire := in.ln, in.tr, in.wire
	in.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range conns {
		c.CloseWithError(0, "")
	}
	if tr != nil {
		tr.Close()
	}
	if wire != nil {
		wire.Close()
	}
	in.wg.Wait()
	return nil
}
