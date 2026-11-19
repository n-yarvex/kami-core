package inbound

import (
	"encoding/json"
	"fmt"
	"net"
	"time"

	"github.com/n-yarvex/kami-core/adapter"
)

func init() {
	adapter.RegisterInbound("mixed", func(env *adapter.InboundEnv, raw json.RawMessage) (adapter.Inbound, error) {
		var o struct {
			Users []User `json:"users"`
			UDP   *bool  `json:"udp"`
		}
		if err := adapter.Decode(raw, &o); err != nil {
			return nil, fmt.Errorf("mixed: %w", err)
		}
		u, err := newUsers(o.Users)
		if err != nil {
			return nil, fmt.Errorf("mixed: %w", err)
		}
		m := &mixed{
			base:  base{env: env, typ: "mixed"},
			socks: &socksInbound{base: base{env: env, typ: "mixed"}, users: u, udp: o.UDP == nil || *o.UDP},
			http:  &httpInbound{base: base{env: env, typ: "mixed"}, users: u},
		}
		return m, nil
	})
}

type mixed struct {
	base
	socks *socksInbound
	http  *httpInbound
}

func (m *mixed) Start() error {
	return m.serve(func(conn net.Conn) {
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
		bc := wrap(conn)
		first, err := bc.r.Peek(1)
		if err != nil {
			return
		}
		if first[0] == socksVersion {
			m.socks.handle(bc)
			return
		}
		m.http.handle(bc)
	})
}
