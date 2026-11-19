package core

import (
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"

	"github.com/n-yarvex/kami-core/config"
	"github.com/n-yarvex/kami-core/klog"
)

type Manager struct {
	path string
	mu   sync.Mutex
	cur  *Instance
}

func NewManager(path string) *Manager { return &Manager{path: path} }

func (m *Manager) boot(cfg *config.Config) (*Instance, error) {
	log, closer, err := klog.New(cfg.Log, os.Stderr)
	if err != nil {
		return nil, err
	}
	in, err := New(cfg, log)
	if err != nil {
		closer.Close()
		return nil, err
	}
	in.SetLogCloser(closer)
	in.reload = m.Reload
	if err := in.Start(); err != nil {
		in.Close()
		return nil, err
	}
	return in, nil
}

func (m *Manager) Start() error {
	cfg, err := config.Load(m.path)
	if err != nil {
		return err
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	in, err := m.boot(cfg)
	if err != nil {
		return err
	}
	m.cur = in
	return nil
}

func (m *Manager) Instance() *Instance {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.cur
}

func (m *Manager) Reload() error {
	next, err := config.Load(m.path)
	if err != nil {
		return fmt.Errorf("reload refused, keeping current config: %w", err)
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	old := m.cur
	trial, err := New(next, slog.New(slog.DiscardHandler))
	if err != nil {
		return fmt.Errorf("reload refused, keeping current config: %w", err)
	}
	trial.Close()

	oldCfg := old.cfg
	old.Close()
	in, err := m.boot(next)
	if err == nil {
		m.cur = in
		return nil
	}
	back, berr := m.boot(oldCfg)
	if berr != nil {
		m.cur = nil
		return fmt.Errorf("reload failed (%v) and rollback failed too: %w", err, berr)
	}
	m.cur = back
	return fmt.Errorf("reload failed, previous config restored: %w", err)
}

func (m *Manager) Close() {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.cur != nil {
		m.cur.Close()
		m.cur = nil
	}
}

func (m *Manager) Run() error {
	if err := m.Start(); err != nil {
		return err
	}
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGHUP, syscall.SIGINT, syscall.SIGTERM)
	for s := range sig {
		if s == syscall.SIGHUP {
			if err := m.Reload(); err != nil {
				if cur := m.Instance(); cur != nil {
					cur.log.Error("reload", "err", err)
				} else {
					fmt.Fprintln(os.Stderr, "reload:", err)
				}
			} else {
				m.Instance().log.Info("configuration reloaded")
			}
			continue
		}
		m.Close()
		return nil
	}
	return nil
}
