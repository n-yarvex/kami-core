package relay

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
	"github.com/n-yarvex/kami-core/bufpool"
)

const maxDatagram = 65535

func Packets(ctx context.Context, client, remote adapter.PacketConn, idle time.Duration, m Meter) {
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		remote.Close()
	})
	defer stop()

	var (
		wg   sync.WaitGroup
		mu   sync.Mutex
		last = time.Now()
	)
	touch := func() {
		mu.Lock()
		last = time.Now()
		mu.Unlock()
	}
	idleFor := func() time.Duration {
		mu.Lock()
		defer mu.Unlock()
		return time.Since(last)
	}
	run := func(from, to adapter.PacketConn, count func(int64)) {
		defer wg.Done()
		defer client.Close()
		defer remote.Close()
		buf := bufpool.Get(maxDatagram)
		defer bufpool.Put(buf)
		for {
			_ = from.SetReadDeadline(time.Now().Add(idle))
			n, peer, err := from.ReadPacket(buf)
			if err != nil {
				var ne net.Error
				if errors.As(err, &ne) && ne.Timeout() && idleFor() < idle {
					continue
				}
				return
			}
			touch()
			if err := to.WritePacket(buf[:n], peer); err != nil {
				continue
			}
			if count != nil {
				count(int64(n))
			}
		}
	}
	wg.Add(2)
	go run(client, remote, m.Up)
	go run(remote, client, m.Down)
	wg.Wait()
}
