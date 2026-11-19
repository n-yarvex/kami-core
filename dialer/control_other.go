//go:build !linux

package dialer

import (
	"errors"
	"syscall"
)

func controlFor(iface string, mark uint32) func(network, address string, c syscall.RawConn) error {
	if iface == "" && mark == 0 {
		return nil
	}
	return func(string, string, syscall.RawConn) error {
		return errors.New("bind_interface and routing_mark are only supported on linux")
	}
}
