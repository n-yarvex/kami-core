module github.com/n-yarvex/kami-core

go 1.25.5

replace golang.org/x/sys => github.com/golang/sys v0.47.0

replace golang.org/x/net => github.com/golang/net v0.57.0

replace golang.org/x/crypto => github.com/golang/crypto v0.54.0

replace golang.org/x/text => github.com/golang/text v0.40.0

replace golang.org/x/sync => github.com/golang/sync v0.22.0

require (
	github.com/gorilla/websocket v1.5.3
	github.com/pion/dtls/v3 v3.1.16
	github.com/pion/turn/v4 v4.1.4
	github.com/quic-go/quic-go v0.61.0
	github.com/refraction-networking/utls v1.8.2
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
	golang.zx2c4.com/wireguard v0.0.0-20250521234502-f333402bd9cb
	gvisor.dev/gvisor v0.0.0-20250503011706-39ed1f5ac29c
)

require (
	github.com/andybalholm/brotli v1.0.6 // indirect
	github.com/google/btree v1.1.2 // indirect
	github.com/klauspost/compress v1.17.4 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/stun/v3 v3.0.1 // indirect
	github.com/pion/transport/v3 v3.0.8 // indirect
	github.com/pion/transport/v4 v4.0.1 // indirect
	github.com/pion/transport/v5 v5.0.0 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.14.0 // indirect
)

replace golang.org/x/time => github.com/golang/time v0.14.0

replace golang.zx2c4.com/wireguard => github.com/WireGuard/wireguard-go v0.0.0-20250521234502-f333402bd9cb

replace gvisor.dev/gvisor => github.com/google/gvisor v0.0.0-20250503011706-39ed1f5ac29c
