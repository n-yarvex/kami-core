//go:build linux

package dialer

import (
	"syscall"

	"golang.org/x/sys/unix"
)

func controlFor(iface string, mark uint32) func(network, address string, c syscall.RawConn) error {
	if iface == "" && mark == 0 {
		return nil
	}
	return func(_, _ string, c syscall.RawConn) error {
		var serr error
		err := c.Control(func(fd uintptr) {
			if iface != "" {
				if serr = unix.SetsockoptString(int(fd), unix.SOL_SOCKET, unix.SO_BINDTODEVICE, iface); serr != nil {
					return
				}
			}
			if mark != 0 {
				serr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
			}
		})
		if err != nil {
			return err
		}
		return serr
	}
}
