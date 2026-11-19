package inbound

import (
	"net"

	"github.com/n-yarvex/kami-core/addr"
)

type adapterAddr = addr.Addr

func addrOf(a net.Addr) addr.Addr { return addr.FromNet(a) }
