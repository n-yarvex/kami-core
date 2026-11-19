# kami-core

A small proxy kernel in Go. Each protocol is a plugin that provides an inbound, an outbound, or both,
so the same binary can be a client, a server, or a relay. Five protocols are implemented:

| protocol | inbound | outbound | notes |
|---|---|---|---|
| Shadowsocks 2022 | yes | yes | `2022-blake3-aes-128/256-gcm`, `2022-blake3-chacha20-poly1305`, multi-user (EIH), UDP sessions; own BLAKE3 |
| AnyTLS | yes | yes | padding schemes with server push, session pool, UDP-over-TCP v2 |
| nakis | yes | yes | TLS-in-TLS-shaped transport; includes the fix for the 24-byte NAP record fingerprint |
| MASQUE | yes | yes | HTTP/3 `CONNECT` + `CONNECT-UDP` (RFC 9114 / 9298 / 9297) |
| Juicity | yes | yes | QUIC, wire-compatible with the reference; optional QUIC-layer `noise` injection |

Around them: SOCKS5 / HTTP / mixed inbounds, `direct` / `block` / `selector` / `urltest` / `fallback` outbounds,
a router (domain, suffix, keyword, regex, CIDR, port, user, inbound, network, sniffed protocol, rule sets),
DNS (servers, rules, cache, hosts, strategy), traffic sniffing, a small REST API, and reload on `SIGHUP`.

## Build and run

```
go build -o kami ./cmd/kami
./kami run   -c config.json     # SIGHUP reloads
./kami check -c config.json     # validate and exit
./kami gen uuid | key [bytes] | cert -d dir host...
```

## Configuration shape

```json
{
  "log": { "level": "info" },
  "dns": { "servers": [{ "tag": "d", "address": "udp://1.1.1.1" }], "final": "d" },
  "inbounds": [
    { "type": "mixed", "tag": "in", "listen": "127.0.0.1:1080", "sniff": true }
  ],
  "outbounds": [
    { "type": "anytls", "tag": "proxy", "server": "203.0.113.5:443", "password": "…",
      "tls": { "server_name": "example.com", "pins": ["<sha256 of the public key>"] } },
    { "type": "direct", "tag": "direct" },
    { "type": "block",  "tag": "block" }
  ],
  "route": {
    "rules": [
      { "domain_suffix": ["lan"], "outbound": "direct" },
      { "ip_cidr": ["10.0.0.0/8"], "outbound": "block" }
    ],
    "final": "proxy"
  },
  "api": { "listen": "127.0.0.1:9090", "secret": "…" }
}
```

DNS server addresses need a scheme (`udp://`, `tcp://`, `tls://`, `https://`, or `local`). Unknown keys are errors, not silently ignored. Per-protocol option lists and examples:
`proto/juicity/README.md`, `proto/masque/README.md`. Common inbound keys: `tag`, `listen`, `sniff`, `allow_private`
(inbounds refuse private destinations unless this is set). Common outbound keys: `tag`, `detour`, `bind_interface`,
`routing_mark`, `connect_timeout`, `domain_strategy`.

REST API (when `api` is set): `GET /version`, `/stats`, `/connections`, `/outbounds`;
`DELETE /connections[/{id}]`; `PUT /outbounds/{tag}` (selector choice); `POST /dns/flush`; `POST /reload`.

## Layout

```
adapter/     plugin interfaces and registries (RegisterInbound / RegisterOutbound), strict JSON decoding
core/        manager (reload with rollback), instance, router, connection tracker, API
inbound/     socks, http, mixed          outbound/  direct, block, selector, urltest, fallback
proto/       ss2022  anytls  nakis  masque  juicity  juicity/noise
tlsx/ dns/ dialer/ route/ match/ sniff/ relay/ bufpool/ addr/ klog/ config/
```

Adding a protocol means writing a package that calls `adapter.RegisterInbound` / `RegisterOutbound` in `init()` and
importing it from `include/include.go`.

## nakis 24-byte fix

A bare nakis NAP message is 24 bytes on the wire as a single TLS 1.3 record, the same size as a `close_notify`.
The fix keeps the protocol unchanged and adds no parameter: the padding record and the NAP record are written in one
`Write`, so the 24-byte record never stands alone. 

## Juicity noise

`noise` (see `proto/juicity/README.md`) wraps the UDP socket under QUIC and sends configurable junk datagrams before
the first real datagram of each peer, and again on a random interval. It is a re-implementation of the idea behind
Xray's finalmask `noise`, with per-peer state, non-blocking delays, bounded memory, and an amplification cap on the server.

## Known limits (please read)

- No built-in GeoIP / GeoSite databases. Rule sets are plain lists you supply.
- No TUN / transparent proxy inbound.
- MASQUE: no CONNECT-IP, no HTTP/2 listener. `DialStream` costs one extra round trip.
- Juicity: quic-go has no BBR, so congestion control is quic-go's default.
- Reload rebuilds all inbounds/outbounds: established connections are dropped. A failed reload rolls back to the
  previous configuration.
- AnyTLS: half-close is asymmetric by design of the protocol (a client cannot half-close a stream), and streams share a
  TCP connection so a stalled stream can block its neighbours (head-of-line blocking).
- Detection resistance is not measured. Nothing here claims a detection or throughput number; the tests check
  correctness and interoperability, not stealth or speed.
- Developed and tested on Linux with Go 1.25 only (this copy omits the test suite).

## Prior art and licensing

The protocols are specified by, and verified against, existing implementations: `sing-shadowsocks`, `sing-anytls`,
`anytls-go`, `nakis`, `masque-go` / quic-go's `http3`, and `juicity`. They were read to understand wire formats only;
no source was copied, and a similarity scan of every protocol package against those trees found no shared code beyond
protocol constants (for example the default AnyTLS padding scheme text, which clients and servers must agree on).
Their licenses differ (GPL-3.0, AGPL-3.0, MPL-2.0, MIT). This repository has no LICENSE file yet:
choose one deliberately before publishing. The only runtime dependency outside the standard library and golang.org/x is
quic-go (MIT).

