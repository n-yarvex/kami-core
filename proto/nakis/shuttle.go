package nakis

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"
	"time"

	"github.com/n-yarvex/kami-core/addr"
	"github.com/n-yarvex/kami-core/bufpool"
)

type shuttle struct {
	client *Client
	app    *duplexConn
	pc     *leased
	target addr.Addr
	gate   *Gate

	downDone atomic.Bool
	appDead  atomic.Bool
	wg       sync.WaitGroup

	half   time.Duration
	dlMu   sync.Mutex
	halted bool
}

func (c *Client) shuttle(app *duplexConn, pc *leased, target addr.Addr) {
	s := &shuttle{client: c, app: app, pc: pc, target: target, half: c.opts.HalfCloseTimeout}
	plan, pad, fill := c.flight(len(pc.first), pc.inner)
	s.gate = NewGate(GateOptions{
		Pack:  c.opts.SendPack,
		Tail:  c.opts.SendTail,
		Quiet: c.opts.SendQuiet,
		Head:  Headroom,
		Plan:  plan,
		Pad:   pad,
		Fill:  fill,
	}, s.send)

	s.wg.Add(2)
	go s.downstream()
	go s.upstream()
	s.wg.Wait()

	s.gate.Close()
	if !pc.napSent.Load() && !pc.broken.Load() {
		pc.napSent.Store(true)
		if err := pc.mc.Nap(); err != nil {
			pc.broken.Store(true)
		}
	}
}

func (s *shuttle) send(wire []byte, pad int) error {
	err := s.pc.mc.SendWirePad(wire, pad)
	if err != nil {
		s.pc.broken.Store(true)
	}
	return err
}

func (s *shuttle) kickApp() {
	s.dlMu.Lock()
	s.halted = true
	_ = s.app.SetReadDeadline(time.Now())
	s.dlMu.Unlock()
}

func (s *shuttle) armApp() {
	s.dlMu.Lock()
	if !s.halted {
		_ = s.app.SetReadDeadline(time.Now().Add(s.half))
	}
	s.dlMu.Unlock()
}

func (s *shuttle) armTunnel() {
	if !s.pc.napSent.Load() {
		return
	}
	s.dlMu.Lock()
	defer s.dlMu.Unlock()
	if s.appDead.Load() {
		_ = s.pc.mc.SetReadDeadline(time.Now().Add(s.client.drainWindow()))
		return
	}
	_ = s.pc.mc.SetReadDeadline(time.Now().Add(s.half))
}

func (s *shuttle) deliver(p []byte) {
	if s.appDead.Load() {
		return
	}
	if _, err := s.app.Write(p); err != nil {
		s.dlMu.Lock()
		s.appDead.Store(true)
		s.dlMu.Unlock()
		s.kickApp()
		s.armTunnel()
	}
}

func (s *shuttle) downstream() {
	defer s.wg.Done()
	defer func() {
		s.downDone.Store(true)
		if s.pc.broken.Load() {
			s.kickApp()
		}
	}()
	mc := s.pc.mc

	if err := mc.ReadReply(); err != nil {
		s.pc.broken.Store(true)
		var mew *PeerError
		if errors.As(err, &mew) {
			s.client.log.Warn("the server could not connect to the destination", "dest", s.target.String(), "err", err)
			s.app.abort(fmt.Errorf("nakis: remote connect: %w", err))
		} else {
			s.client.log.Debug("tunnel reply failed", "dest", s.target.String(), "err", err)
			s.client.hintOnce(err)
			s.app.abort(fmt.Errorf("nakis: tunnel: %w", err))
		}
		return
	}
	if rest := mc.TakePending(); rest != nil {
		s.deliver(rest)
		bufpool.Put(rest)
	}
	for {
		s.armTunnel()
		p, err := mc.ReadFrame()
		if err != nil {
			if errors.Is(err, ErrNap) {
				s.pc.napSeen.Store(true)
				if !s.appDead.Load() {
					_ = s.app.CloseWrite()
					s.armApp()
				}
			} else {
				s.pc.broken.Store(true)
				s.app.abort(fmt.Errorf("nakis: tunnel: %w", err))
			}
			return
		}
		s.deliver(p)
		bufpool.Put(p)
	}
}

func (s *shuttle) upstream() {
	defer s.wg.Done()
	buf := bufpool.Get(PackCap)
	defer bufpool.Put(buf)

	s.gate.Feed(s.pc.first)
	for {
		if s.downDone.Load() {
			s.armApp()
		}
		n, err := s.app.Read(buf)
		if n > 0 {
			s.gate.Feed(buf[:n])
		}
		if err != nil {
			break
		}
	}
	if s.pc.broken.Load() {
		return
	}
	s.gate.Flush()
	if s.pc.broken.Load() {
		return
	}
	s.pc.napSent.Store(true)
	if err := s.pc.mc.Nap(); err != nil {
		s.pc.broken.Store(true)
		return
	}
	s.armTunnel()
}
