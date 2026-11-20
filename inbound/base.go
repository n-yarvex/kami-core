package inbound

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
)

const handshakeTimeout = 15 * time.Second

type User struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

type users map[string][sha256.Size]byte

func newUsers(list []User) (users, error) {
	if len(list) == 0 {
		return nil, nil
	}
	u := make(users, len(list))
	for _, e := range list {
		if e.Name == "" || e.Password == "" {
			return nil, errors.New("user name and password must not be empty")
		}
		if _, dup := u[e.Name]; dup {
			return nil, errors.New("duplicate user " + e.Name)
		}
		u[e.Name] = sha256.Sum256([]byte(e.Password))
	}
	return u, nil
}

func (u users) check(name, password string) bool {
	want, ok := u[name]
	got := sha256.Sum256([]byte(password))
	return subtle.ConstantTimeCompare(want[:], got[:]) == 1 && ok
}

type base struct {
	env *adapter.InboundEnv
	typ string

	wrapLn func(net.Listener) net.Listener

	mu     sync.Mutex
	ln     net.Listener
	closed bool
	live   map[net.Conn]struct{}
	wg     sync.WaitGroup
}

func (b *base) Tag() string  { return b.env.Tag }
func (b *base) Type() string { return b.typ }

func (b *base) serve(handle func(conn net.Conn)) error {
	ln, err := b.env.ListenTCP()
	if err != nil {
		return err
	}
	if b.wrapLn != nil {
		ln = b.wrapLn(ln)
	}
	b.mu.Lock()
	b.ln = ln
	b.live = map[net.Conn]struct{}{}
	b.mu.Unlock()
	b.wg.Add(1)
	go func() {
		defer b.wg.Done()
		var backoff time.Duration
		for {
			conn, err := ln.Accept()
			if err != nil {
				if errors.Is(err, net.ErrClosed) {
					return
				}
				backoff = min(max(backoff*2, 5*time.Millisecond), time.Second)
				time.Sleep(backoff)
				continue
			}
			backoff = 0
			b.track(conn, true)
			b.wg.Add(1)
			go func() {
				defer b.wg.Done()
				defer b.track(conn, false)
				handle(conn)
			}()
		}
	}()
	return nil
}

func (b *base) track(c net.Conn, add bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if add {
		if b.closed {
			c.Close()
			return
		}
		b.live[c] = struct{}{}
		return
	}
	delete(b.live, c)
}

func (b *base) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	ln := b.ln
	pending := make([]net.Conn, 0, len(b.live))
	for c := range b.live {
		pending = append(pending, c)
	}
	b.mu.Unlock()
	if ln != nil {
		ln.Close()
	}
	for _, c := range pending {
		c.SetDeadline(time.Now())
	}
	b.wg.Wait()
	return nil
}

type buffered struct {
	net.Conn
	r *bufio.Reader
}

func (b *buffered) Read(p []byte) (int, error) { return b.r.Read(p) }

func (b *buffered) CloseWrite() error {
	if cw, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return errors.New("no half close")
}

func (b *buffered) handoff() net.Conn {
	if b.r.Buffered() == 0 {
		return b.Conn
	}
	return b
}

func wrap(c net.Conn) *buffered {
	return &buffered{Conn: c, r: bufio.NewReaderSize(c, 4096)}
}

func md(env *adapter.InboundEnv, typ, network, user string, conn net.Conn, dest adapterAddr) adapter.Metadata {
	return adapter.Metadata{
		Inbound:     env.Tag,
		InboundType: typ,
		User:        user,
		Network:     network,
		Source:      addrOf(conn.RemoteAddr()),
		Dest:        dest,
	}
}
