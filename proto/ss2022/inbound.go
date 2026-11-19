package ss2022

import (
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/config"
)

func init() {
	adapter.RegisterInbound("ss2022", newInbound)
}

type userOption struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type inboundOptions struct {
	Method           string          `json:"method"`
	Password         string          `json:"password"`
	Users            []userOption    `json:"users"`
	HandshakeTimeout config.Duration `json:"handshake_timeout"`
	UDPTimeout       config.Duration `json:"udp_timeout"`
	DisableUDP       bool            `json:"disable_udp"`
}

const saltLimit = 1 << 20

type inbound struct {
	env     *adapter.InboundEnv
	acc     *acceptor
	udp     bool
	udpLife time.Duration
	pk      *packetServer

	mu     sync.Mutex
	ln     net.Listener
	live   map[net.Conn]struct{}
	closed bool
	wg     sync.WaitGroup
}

func newInbound(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
	var o inboundOptions
	if err := adapter.Decode(raw, &o); err != nil {
		return nil, fmt.Errorf("ss2022: %w", err)
	}
	s, err := suiteFor(o.Method)
	if err != nil {
		return nil, err
	}
	if o.Password == "" {
		return nil, errors.New("ss2022: password is required")
	}
	key, err := s.parseKey(o.Password)
	if err != nil {
		return nil, err
	}
	acc := &acceptor{
		suite:   s,
		key:     key,
		salts:   newSaltCache(saltLimit),
		timeout: o.HandshakeTimeout.Std(),
	}
	if acc.timeout <= 0 {
		acc.timeout = 15 * time.Second
	}
	if len(o.Users) > 0 {
		if s.chacha {
			return nil, errors.New("ss2022: multiple users need an AES method")
		}
		acc.users = map[[16]byte]*account{}
		names := map[string]bool{}
		for i, u := range o.Users {
			if u.Name == "" {
				u.Name = fmt.Sprintf("user%d", i+1)
			}
			uk, err := s.parseKey(u.Password)
			if err != nil {
				return nil, fmt.Errorf("user %q: %w", u.Name, err)
			}
			fp := fingerprint(uk)
			if names[u.Name] || acc.users[fp] != nil {
				return nil, fmt.Errorf("ss2022: user %q duplicates another user", u.Name)
			}
			names[u.Name] = true
			acc.users[fp] = &account{name: u.Name, key: uk}
		}
	}
	life := o.UDPTimeout.Std()
	if life <= 0 {
		life = 5 * time.Minute
	}
	if life < saltLife {
		return nil, errors.New("ss2022: udp_timeout must be at least 60s")
	}
	return &inbound{env: env, acc: acc, udp: !o.DisableUDP, udpLife: life, live: map[net.Conn]struct{}{}}, nil
}

func (i *inbound) Tag() string  { return i.env.Tag }
func (i *inbound) Type() string { return "ss2022" }

func (i *inbound) Start() error {
	ln, err := i.env.ListenTCP()
	if err != nil {
		return err
	}
	var sock net.PacketConn
	if i.udp {
		if sock, err = i.env.ListenUDP(); err != nil {
			ln.Close()
			return err
		}
	}
	i.mu.Lock()
	i.ln = ln
	if sock != nil {
		i.pk = newPacketServer(i.acc, sock, i.env, i.udpLife)
		i.pk.run()
	}
	i.mu.Unlock()
	i.wg.Add(1)
	go i.loop(ln)
	return nil
}

func (i *inbound) loop(ln net.Listener) {
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
		if !i.hold(conn) {
			conn.Close()
			continue
		}
		i.wg.Add(1)
		go func() {
			defer i.wg.Done()
			i.serve(conn)
		}()
	}
}

func (i *inbound) hold(c net.Conn) bool {
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.closed {
		return false
	}
	i.live[c] = struct{}{}
	return true
}

func (i *inbound) release(c net.Conn) {
	i.mu.Lock()
	delete(i.live, c)
	i.mu.Unlock()
}

func (i *inbound) serve(conn net.Conn) {
	t, user, dest, err := i.acc.accept(conn)
	if err != nil {
		i.env.Log.Debug("ss2022 handshake failed", "from", conn.RemoteAddr().String())
		i.acc.quarantine(conn)
		i.release(conn)
		return
	}
	i.env.Router.Stream(i.env.Ctx, t, adapter.Metadata{
		Inbound:     i.env.Tag,
		InboundType: "ss2022",
		User:        user,
		Network:     "tcp",
		Source:      addr.FromNet(conn.RemoteAddr()),
		Dest:        dest,
	})
	i.release(conn)
}

func (i *inbound) Close() error {
	i.mu.Lock()
	if i.closed {
		i.mu.Unlock()
		return nil
	}
	i.closed = true
	ln, pk := i.ln, i.pk
	pending := make([]net.Conn, 0, len(i.live))
	for c := range i.live {
		pending = append(pending, c)
	}
	i.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range pending {
		c.SetDeadline(time.Now())
	}
	if pk != nil {
		pk.shut()
	}
	i.wg.Wait()
	return nil
}
