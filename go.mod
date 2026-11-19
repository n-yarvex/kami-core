module github.com/n-yarvex/kami-core

go 1.25.5

replace golang.org/x/sys => github.com/golang/sys v0.47.0

replace golang.org/x/net => github.com/golang/net v0.57.0

replace golang.org/x/crypto => github.com/golang/crypto v0.54.0

replace golang.org/x/text => github.com/golang/text v0.40.0

replace golang.org/x/sync => github.com/golang/sync v0.22.0

require (
	github.com/quic-go/quic-go v0.61.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.56.0
	golang.org/x/sys v0.47.0
)

require (
	github.com/quic-go/qpack v0.6.0 // indirect
	golang.org/x/text v0.40.0 // indirect
)
