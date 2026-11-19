package relay

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"time"

	"github.com/n-yarvex/kami-core/bufpool"
)

const chunk = 32 << 10

var noHalfEnd = 5 * time.Second

type Meter struct {
	Up   func(int64)
	Down func(int64)
}

func Stream(ctx context.Context, client, remote net.Conn, m Meter) {
	stop := context.AfterFunc(ctx, func() {
		client.Close()
		remote.Close()
	})
	defer stop()

	var (
		wg    sync.WaitGroup
		once  sync.Once
		timer *time.Timer
	)
	linger := func() {
		once.Do(func() {
			timer = time.AfterFunc(noHalfEnd, func() {
				client.Close()
				remote.Close()
			})
		})
	}
	wg.Add(2)
	go func() {
		defer wg.Done()
		pump(remote, client, m.Up, linger)
	}()
	go func() {
		defer wg.Done()
		pump(client, remote, m.Down, linger)
	}()
	wg.Wait()
	if timer != nil {
		timer.Stop()
	}
	client.Close()
	remote.Close()
}

func pump(dst, src net.Conn, count func(int64), linger func()) {
	n, err := copyConn(dst, src, count)
	if count != nil && n > 0 && isSplice(dst, src) {
		count(n)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		dst.Close()
		src.Close()
		return
	}
	if cw, ok := dst.(interface{ CloseWrite() error }); ok {
		if cw.CloseWrite() == nil {
			return
		}
	}
	linger()
}

func isSplice(dst, src net.Conn) bool {
	_, a := dst.(*net.TCPConn)
	_, b := src.(*net.TCPConn)
	return a && b
}

func copyConn(dst, src net.Conn, count func(int64)) (int64, error) {
	if isSplice(dst, src) {
		return io.Copy(dst, src)
	}
	buf := bufpool.Get(chunk)
	defer bufpool.Put(buf)
	var total int64
	for {
		n, rerr := src.Read(buf)
		if n > 0 {
			w, werr := dst.Write(buf[:n])
			total += int64(w)
			if count != nil {
				count(int64(w))
			}
			if werr != nil {
				return total, werr
			}
			if w < n {
				return total, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if errors.Is(rerr, io.EOF) {
				return total, nil
			}
			return total, rerr
		}
	}
}
