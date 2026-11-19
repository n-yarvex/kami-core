package nakis

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

type User struct {
	Name string
	UUID string
}

type ServiceOptions struct {
	Log              *slog.Logger
	Router           adapter.Router
	Tag              string
	Users            []User
	Handshake        func(ctx context.Context, conn net.Conn) (net.Conn, error)
	HandshakeTimeout time.Duration
	IdleTimeout      time.Duration
	HalfCloseTimeout time.Duration
	SendPack         int
	SendTail         int
	SendQuiet        int
	MergePack        int
	MaxQueue         int
	DisableUDP       bool
	UDPIdleTimeout   time.Duration
	UDPJitter        time.Duration
}

type serviceUser struct {
	name  string
	guard *Guard
}

type Service struct {
	opts  ServiceOptions
	log   *slog.Logger
	users atomic.Pointer[[]*serviceUser]

	skewNote atomic.Bool
	turnNote atomic.Bool
	turned   atomic.Int64

	access  sync.Mutex
	tunnels map[*Tunnel]struct{}
	closed  bool
	routed  sync.WaitGroup
}

type origin struct {
	user   string
	source addr.Addr
}

func NewService(options ServiceOptions) (*Service, error) {
	if options.Router == nil {
		return nil, errors.New("nakis: missing router")
	}
	if options.Log == nil {
		options.Log = slog.New(slog.DiscardHandler)
	}
	options.HandshakeTimeout = orDuration(options.HandshakeTimeout, 10*time.Second)
	options.IdleTimeout = orDuration(options.IdleTimeout, 120*time.Second)
	options.HalfCloseTimeout = orDuration(options.HalfCloseTimeout, 120*time.Second)
	options.SendPack = clamp(orInt(options.SendPack, 32*1024), 1024, PackCap)
	options.SendTail = clamp(orInt(options.SendTail, 512), 0, options.SendPack-1)
	options.SendQuiet = clamp(orInt(options.SendQuiet, 4), 0, 64)
	options.MergePack = clamp(orInt(options.MergePack, 20*1024), 1024, FrameCap)
	options.MaxQueue = clamp(orInt(options.MaxQueue, 4*1024*1024), 64*1024, 256*1024*1024)
	options.UDPIdleTimeout = orDuration(options.UDPIdleTimeout, 300*time.Second)
	options.UDPJitter = jitterSpan(options.UDPJitter)
	s := &Service{
		opts:    options,
		log:     options.Log,
		tunnels: make(map[*Tunnel]struct{}),
	}
	if err := s.UpdateUsers(options.Users); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Service) UpdateUsers(users []User) error {
	if len(users) == 0 {
		return errors.New("nakis: missing users")
	}
	list := make([]*serviceUser, 0, len(users))
	for index, user := range users {
		id, err := ParseUUID(user.UUID)
		if err != nil {
			return fmt.Errorf("nakis: users[%d]: invalid uuid: %w", index, err)
		}
		list = append(list, &serviceUser{name: user.Name, guard: NewGuard(id)})
	}
	s.users.Store(&list)
	return nil
}

func (s *Service) Close() error {
	s.access.Lock()
	s.closed = true
	tunnels := make([]*Tunnel, 0, len(s.tunnels))
	for mc := range s.tunnels {
		tunnels = append(tunnels, mc)
	}
	s.access.Unlock()
	for _, mc := range tunnels {
		_ = mc.Close()
	}
	s.routed.Wait()
	return nil
}

func (s *Service) route(fn func()) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return false
	}
	s.routed.Add(1)
	go func() {
		defer s.routed.Done()
		fn()
	}()
	return true
}

func (s *Service) track(mc *Tunnel) bool {
	s.access.Lock()
	defer s.access.Unlock()
	if s.closed {
		return false
	}
	s.tunnels[mc] = struct{}{}
	return true
}

func (s *Service) untrack(mc *Tunnel) {
	s.access.Lock()
	delete(s.tunnels, mc)
	s.access.Unlock()
}

func (s *Service) NewConnection(ctx context.Context, conn net.Conn, source addr.Addr) error {
	var batch *Batcher
	secured := conn
	if s.opts.Handshake != nil {
		batch = NewBatcher(conn)
		hctx, cancel := context.WithTimeout(ctx, s.opts.HandshakeTimeout)
		tc, err := s.opts.Handshake(hctx, batch)
		cancel()
		if err != nil {
			return fmt.Errorf("nakis: tls handshake: %w", err)
		}
		secured = tc
	}
	mc := WrapTunnel(secured, batch)
	if s.opts.Handshake != nil {
		bind, err := ExportBinding(secured)
		if err != nil {
			_ = secured.Close()
			return err
		}
		mc.bind = bind
	}
	if !s.track(mc) {
		_ = mc.Close()
		return net.ErrClosed
	}
	s.serve(ctx, mc, source)
	return nil
}

func (s *Service) serve(ctx context.Context, mc *Tunnel, source addr.Addr) {
	defer func() {
		if r := recover(); r != nil {
			s.log.Error("recovered from a crash while serving a tunnel", "source", source.String(), "panic", r)
		}
		s.untrack(mc)
		_ = mc.Close()
	}()

	user, err := s.admit(mc, source)
	if err != nil {
		return
	}
	who := origin{user: user.name, source: source}
	for {
		_ = mc.SetReadDeadline(time.Now().Add(s.opts.IdleTimeout))
		again, err := s.serveOne(ctx, mc, who)
		if err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, ErrNap) && ctx.Err() == nil {
				s.log.Debug("request ended", "source", source.String(), "err", err)
			}
			return
		}
		if !again {
			s.log.Debug("tunnel is not reusable, closing", "source", source.String())
			return
		}
	}
}

var errTurnedAway = errors.New("turned away")

func (s *Service) admit(mc *Tunnel, source addr.Addr) (*serviceUser, error) {
	frame, prefix, err := mc.ReadFirst(s.opts.IdleTimeout, min(s.opts.HandshakeTimeout, firstBody))
	if err != nil {
		return nil, err
	}
	if frame == nil {
		s.refuse(source, errors.New("not a nakis frame"))
		s.decoy(mc, prefix)
		return nil, errTurnedAway
	}
	if len(frame) < ProofSize {
		bufpool.Put(frame)
		s.refuse(source, ErrBadMac)
		s.decoy(mc, nil)
		return nil, errTurnedAway
	}
	var matched *serviceUser
	verdict := ErrBadMac
	for _, user := range *s.users.Load() {
		err := user.guard.Accept(frame[:ProofSize], mc.bind)
		if err == nil {
			matched = user
			break
		}
		if !errors.Is(err, ErrBadMac) {
			verdict = err
		}
	}
	if matched == nil {
		bufpool.Put(frame)
		s.refuse(source, verdict)
		s.decoy(mc, nil)
		return nil, errTurnedAway
	}
	if len(frame) == ProofSize {
		bufpool.Put(frame)
		return matched, nil
	}
	mc.Unread(frame, ProofSize)
	return matched, nil
}

func (s *Service) refuse(source addr.Addr, err error) {
	s.turned.Add(1)
	if s.turnNote.CompareAndSwap(false, true) {
		time.AfterFunc(time.Minute, func() {
			n := s.turned.Swap(0)
			s.turnNote.Store(false)
			s.log.Warn("turned away connections without a valid proof in the last minute, if one is yours check the uuid and the clock", "count", n)
		})
	}
	var stale *StaleError
	if errors.As(err, &stale) && s.skewNote.CompareAndSwap(false, true) {
		s.log.Warn("a client clock is off the server clock", "skew", stale.Skew.Round(time.Second), "allowed", ProofWindow, "source", source.String())
		time.AfterFunc(10*time.Second, func() { s.skewNote.Store(false) })
		return
	}
	s.log.Debug("proof refused", "source", source.String(), "err", err)
}

func readN(mc *Tunnel, n int) ([]byte, error) {
	buf := make([]byte, n)
	_, err := io.ReadFull(mc, buf)
	return buf, err
}

func (s *Service) serveOne(ctx context.Context, mc *Tunnel, who origin) (bool, error) {
	version, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if ctx.Err() != nil {
		return false, ctx.Err()
	}
	if version != HelloVersion {
		return false, fmt.Errorf("nakis: invalid protocol version 0x%x", version)
	}
	cmd, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if cmd != CmdConnect {
		return false, fmt.Errorf("nakis: unknown command 0x%x", cmd)
	}
	idLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if idLen > 0 {
		if _, err = readN(mc, int(idLen)); err != nil {
			return false, err
		}
	}
	hostLen, err := mc.ReadByte()
	if err != nil {
		return false, err
	}
	if hostLen == 0 {
		return false, errors.New("nakis: connect host is empty")
	}
	host, err := readN(mc, int(hostLen))
	if err != nil {
		return false, err
	}
	pb, err := readN(mc, 2)
	if err != nil {
		return false, err
	}
	_ = mc.SetReadDeadline(time.Time{})

	if string(host) == uotHost {
		return s.servePackets(ctx, mc, who), nil
	}
	destination := addr.FromHost(string(host), binary.BigEndian.Uint16(pb))
	if !destination.IsValid() {
		return false, errors.New("nakis: connect host is malformed")
	}
	return s.serveStream(ctx, mc, who, destination), nil
}

func (s *Service) serveStream(ctx context.Context, mc *Tunnel, who origin, destination addr.Addr) bool {
	s.log.Debug("stream", "source", who.source.String(), "dest", destination.String())
	target, user := newDuplex(duplexAddr(destination.String()), duplexAddr(who.source.String()))
	md := adapter.Metadata{
		Inbound:     s.opts.Tag,
		InboundType: "nakis",
		User:        who.user,
		Network:     "tcp",
		Source:      who.source,
		Dest:        destination,
	}
	if !s.route(func() {
		s.opts.Router.Stream(ctx, user, md)
		_ = user.Close()
	}) {
		_ = target.Close()
		_ = user.Close()
		return false
	}
	clean := newBridge(s, mc, target, tlsLike(strconv.Itoa(int(destination.Port())))).run()
	_ = target.Close()
	_ = user.Close()
	return clean
}

func errnoOf(err error) byte {
	var e syscall.Errno
	if errors.As(err, &e) {
		return byte(e)
	}
	return 0
}

type bridge struct {
	srv    *Service
	tun    *Tunnel
	target *duplexConn

	access sync.Mutex
	cond   *sync.Cond
	box    *Box
	closed bool
	eof    bool

	gate *Gate

	wMu     sync.Mutex
	greeted bool

	napSeen      atomic.Bool
	napSent      atomic.Bool
	broken       atomic.Bool
	feedWG       sync.WaitGroup
	gatherFinish chan struct{}
	half         time.Duration
}

func newBridge(srv *Service, tun *Tunnel, target *duplexConn, inner bool) *bridge {
	opts := srv.opts
	n := &bridge{
		srv:          srv,
		tun:          tun,
		target:       target,
		box:          NewBox(opts.MergePack, 0),
		gatherFinish: make(chan struct{}),
		half:         opts.HalfCloseTimeout,
	}
	n.cond = sync.NewCond(&n.access)
	n.gate = NewGate(GateOptions{
		Pack:  opts.SendPack,
		Tail:  opts.SendTail,
		Quiet: opts.SendQuiet,
		Head:  Headroom,
		Plan:  shapePlan(false, inner, 0),
		Pad:   true,
		Fill:  shapeFill,
	}, n.write)
	return n
}

func (n *bridge) write(wire []byte, pad int) error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if n.greeted {
		return n.fail(n.tun.SendWirePad(wire, pad))
	}
	n.greeted = true
	pre := bufpool.Get(len(wire) + 1)
	pre[Headroom] = RespOK
	copy(pre[Headroom+1:], wire[Headroom:])
	err := n.tun.SendWirePad(pre, pad)
	bufpool.Put(pre)
	return n.fail(err)
}

func (n *bridge) fail(err error) error {
	if err != nil {
		n.broken.Store(true)
	}
	return err
}

func (n *bridge) sendNap() error {
	n.wMu.Lock()
	defer n.wMu.Unlock()
	if !n.greeted {
		n.greeted = true
		if err := n.tun.Send(nil, OKByte); err != nil {
			return err
		}
	}
	return n.tun.Nap()
}

func (n *bridge) stop() {
	n.access.Lock()
	n.closed = true
	n.box.Drain()
	n.cond.Broadcast()
	n.access.Unlock()
	_ = n.target.Close()
}

func (n *bridge) deposit(p []byte) bool {
	n.access.Lock()
	defer n.access.Unlock()
	for n.box.Size() >= n.srv.opts.MaxQueue && !n.closed {
		n.cond.Wait()
	}
	if n.closed {
		return false
	}
	n.box.Push(p)
	n.cond.Broadcast()
	return true
}

func (n *bridge) gather() {
	defer close(n.gatherFinish)
	for {
		if n.napSent.Load() {
			_ = n.tun.SetReadDeadline(time.Now().Add(n.half))
		}
		p, err := n.tun.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrNap) {
				n.napSeen.Store(true)
				_ = n.target.SetReadDeadline(time.Now().Add(n.half))
			} else {
				n.broken.Store(true)
			}
			n.access.Lock()
			n.eof = true
			n.cond.Broadcast()
			n.access.Unlock()
			return
		}
		if !n.deposit(p) {
			bufpool.Put(p)
		}
	}
}

func (n *bridge) feed() {
	defer n.feedWG.Done()
	for {
		n.access.Lock()
		for n.box.Empty() && !n.eof && !n.closed {
			n.cond.Wait()
		}
		if n.closed {
			n.access.Unlock()
			return
		}
		if n.box.Empty() {
			n.access.Unlock()
			if n.broken.Load() {
				n.stop()
			} else {
				_ = n.target.CloseWrite()
			}
			return
		}
		d, merged := n.box.Merge(nil)
		n.cond.Broadcast()
		n.access.Unlock()

		_, err := n.target.Write(d)
		if !merged {
			bufpool.Put(d)
		}
		if err != nil {
			n.srv.log.Debug("target write failed", "err", err)
			n.stop()
			return
		}
	}
}

func (n *bridge) mill() (clean bool) {
	wire := bufpool.Get(Headroom + PackCap)
	defer bufpool.Put(wire)
	half := PackCap >> 1
	defer func() {
		n.gate.Flush()
		n.gate.Close()
	}()

	for {
		if n.napSeen.Load() {
			_ = n.target.SetReadDeadline(time.Now().Add(n.half))
		}
		k, err := n.target.Read(wire[Headroom:])
		if k > 0 {
			if k >= half {
				n.gate.Flush()
				if n.write(wire[:Headroom+k], 0) != nil {
					return
				}
			} else {
				n.gate.Feed(wire[Headroom : Headroom+k])
			}
			if n.broken.Load() {
				return
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return !n.broken.Load()
			}
			if !errors.Is(err, net.ErrClosed) {
				n.srv.log.Debug("target read ended", "err", err)
			}
			return false
		}
	}
}

func (n *bridge) run() bool {
	if lead := n.tun.TakePending(); lead != nil {
		n.box.Push(lead)
	}
	n.feedWG.Add(1)
	go n.feed()
	go n.gather()

	if !n.mill() {
		n.stop()
		n.feedWG.Wait()
		n.dispose()
		if n.broken.Load() || n.sendNap() != nil {
			return false
		}
		n.napSent.Store(true)
		_ = n.tun.SetReadDeadline(time.Now().Add(serverDrain))
		<-n.gatherFinish
		return n.finish()
	}

	if n.sendNap() != nil {
		n.stop()
		n.feedWG.Wait()
		n.dispose()
		return false
	}
	n.napSent.Store(true)
	_ = n.tun.SetReadDeadline(time.Now().Add(n.half))
	<-n.gatherFinish
	guard := time.AfterFunc(n.half, n.stop)
	n.feedWG.Wait()
	guard.Stop()
	n.stop()
	n.dispose()
	return n.finish()
}

func (n *bridge) dispose() {
	n.access.Lock()
	n.box.Dispose()
	n.access.Unlock()
}

func (n *bridge) finish() bool {
	if n.broken.Load() || !n.napSeen.Load() {
		return false
	}
	_ = n.tun.SetReadDeadline(time.Time{})
	return true
}

var httpMethods = []string{"GET ", "HEAD ", "POST ", "PUT ", "DELETE ", "OPTIONS ", "PATCH ", "CONNECT ", "TRACE ", "PRI "}

const decoyWelcome = "<!DOCTYPE html>\n<html>\n<head>\n<title>Welcome to nginx!</title>\n<style>\nhtml { color-scheme: light dark; }\nbody { width: 35em; margin: 0 auto;\nfont-family: Tahoma, Verdana, Arial, sans-serif; }\n</style>\n</head>\n<body>\n<h1>Welcome to nginx!</h1>\n<p>If you see this page, the nginx web server is successfully installed and\nworking. Further configuration is required.</p>\n\n<p>For online documentation and support please refer to\n<a href=\"http://nginx.org/\">nginx.org</a>.<br/>\nCommercial support is available at\n<a href=\"http://nginx.com/\">nginx.com</a>.</p>\n\n<p><em>Thank you for using nginx.</em></p>\n</body>\n</html>\n"

func errorPage(code int, text string) string {
	return fmt.Sprintf("<html>\r\n<head><title>%d %s</title></head>\r\n<body>\r\n<center><h1>%d %s</h1></center>\r\n<hr><center>nginx</center>\r\n</body>\r\n</html>\r\n", code, text, code, text)
}

func decoyReply(head []byte) []byte {
	line := string(head)
	if i := strings.Index(line, "\r\n"); i >= 0 {
		line = line[:i]
	}
	status, text, body, isHead := 400, "Bad Request", errorPage(400, "Bad Request"), false
	for _, m := range httpMethods {
		if strings.HasPrefix(line, m) {
			isHead = m == "HEAD "
			if strings.HasPrefix(line[len(m):], "/ ") || strings.HasPrefix(line[len(m):], "/index.html ") {
				status, text, body = 200, "OK", decoyWelcome
			} else {
				status, text, body = 404, "Not Found", errorPage(404, "Not Found")
			}
			break
		}
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "HTTP/1.1 %d %s\r\nServer: nginx\r\nDate: %s\r\nContent-Type: text/html\r\nContent-Length: %d\r\nConnection: close\r\n\r\n",
		status, text, time.Now().UTC().Format(http.TimeFormat), len(body))
	if !isHead {
		out.WriteString(body)
	}
	return out.Bytes()
}

func (s *Service) decoy(mc *Tunnel, prefix []byte) {
	_ = mc.Conn.SetDeadline(time.Now().Add(decoyWait))
	head := append([]byte(nil), prefix...)
	buf := make([]byte, 1024)
	for len(head) < decoyHead && !bytes.Contains(head, []byte("\r\n\r\n")) {
		n, err := mc.rd.Read(buf)
		head = append(head, buf[:n]...)
		if err != nil {
			break
		}
	}
	_, _ = mc.Conn.Write(decoyReply(head))
}
