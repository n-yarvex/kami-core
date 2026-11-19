package ss2022

import (
	"sync"
	"time"
)

const saltLife = 60 * time.Second

type saltCache struct {
	mu    sync.Mutex
	cur   map[string]struct{}
	prev  map[string]struct{}
	flip  time.Time
	limit int
}

func newSaltCache(limit int) *saltCache {
	return &saltCache{cur: map[string]struct{}{}, prev: map[string]struct{}{}, flip: time.Now(), limit: limit}
}

func (c *saltCache) claim(salt []byte, now time.Time) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if elapsed := now.Sub(c.flip); elapsed >= saltLife {
		c.prev, c.cur = c.cur, make(map[string]struct{}, len(c.prev))
		if elapsed >= 2*saltLife {
			c.prev = map[string]struct{}{}
		}
		c.flip = now
	}
	key := string(salt)
	if _, seen := c.cur[key]; seen {
		return false
	}
	if _, seen := c.prev[key]; seen {
		return false
	}
	if len(c.cur) >= c.limit {
		return false
	}
	c.cur[key] = struct{}{}
	return true
}

const windowBits = 2048

type window struct {
	top  uint64
	seen [windowBits / 64]uint64
	used bool
}

func (w *window) fresh(id uint64) bool {
	if !w.used || id > w.top {
		return true
	}
	if w.top-id >= windowBits {
		return false
	}
	return w.seen[(id/64)%(windowBits/64)]&(1<<(id%64)) == 0
}

func (w *window) commit(id uint64) {
	if !w.used {
		w.used = true
		w.top = id
		w.seen = [windowBits / 64]uint64{}
	} else if id > w.top {
		gap := id - w.top
		if gap >= windowBits {
			w.seen = [windowBits / 64]uint64{}
		} else {
			for i := w.top + 1; i <= id; i++ {
				w.seen[(i/64)%(windowBits/64)] &^= 1 << (i % 64)
			}
		}
		w.top = id
	}
	w.seen[(id/64)%(windowBits/64)] |= 1 << (id % 64)
}
