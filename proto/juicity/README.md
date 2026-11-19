# juicity

QUIC-based proxy, inbound and outbound, plus an optional QUIC-layer noise injector.
Wire-compatible with the reference implementation (verified in both directions against
the official `juicity-server` and `juicity-client` binaries, see `interop/juicity`).

## What is implemented

- QUIC + TLS 1.3, ALPN forced to `h3`.
- Authentication on a unidirectional stream: `version 0, cmd 0, uuid(16), token(32)`, where
  `token = ExportKeyingMaterial(label = raw uuid bytes, context = password, 32)`.
  A bad token closes the whole QUIC connection; proxy streams are not processed before auth succeeds.
- TCP: one bidirectional stream per connection. The proxy header travels with the first payload;
  if the application sends nothing for 100 ms the header is sent alone (server-first protocols work).
- UDP: UDP-over-stream, one stream per flow, `[addr][len u16][payload]` per datagram in both directions.
  Domain destinations are resolved by the core's router once per flow.
- Client: one QUIC connection is reused. When the server's stream limit is reached a further connection is
  opened (up to 8); reconnects are de-duplicated and back off from 200 ms to 5 s.
- Server: multi-user (`users`), the user name is passed to the router.

## Things to know

- Address type bytes on the wire are `1` IPv4, `3` domain, `4` IPv6 (as the reference implementation sends them).
  The prose spec in the reference repository lists `0/1/2`; the deployed implementation is what we follow.
- Congestion control is quic-go's default controller. quic-go has no BBR; the spec asks for it, we do not fake it.
- No 0-RTT.

## Options

Outbound:

```json
{
  "type": "juicity",
  "server": "203.0.113.5:443",
  "uuid": "6f2a1f0e-3c3f-4d0b-9a55-0d6a4b9d1a10",
  "password": "change-me",
  "tls": { "server_name": "example.com", "pins": ["hex sha256 of the certificate public key"] },
  "keepalive": "10s",
  "idle_timeout": "30s",
  "stream_window_mib": 8,
  "conn_window_mib": 20,
  "udp_timeout": "3m",
  "disable_udp": false,
  "noise": { "reset_min": 30, "reset_max": 90, "items": [ { "rand_min": 40, "rand_max": 200, "delay_max": 20 } ] }
}
```

Inbound:

```json
{
  "type": "juicity",
  "listen": ":443",
  "users": [ { "name": "ann", "uuid": "6f2a1f0e-3c3f-4d0b-9a55-0d6a4b9d1a10", "password": "change-me" } ],
  "tls": { "certificate": "/etc/kami/fullchain.pem", "key": "/etc/kami/key.pem" },
  "max_streams": 1024,
  "udp_timeout": "4m",
  "noise": { "reset_min": 30, "reset_max": 90, "items": [ { "packet": "c0ffee" } ] }
}
```

## noise

A `net.PacketConn` wrapper (package `proto/juicity/noise`, usable on its own) that sends a train of junk
UDP datagrams to a peer before the first real datagram, and again after a random interval between
`reset_min` and `reset_max` seconds (`0` means once per peer).
It is applied underneath QUIC on both the client socket and the server socket when `noise` is set.
Either side can enable it independently: QUIC drops datagrams it cannot parse.

Item forms (exactly one per item):

| form | fields |
|---|---|
| fixed bytes | `packet` (hex) |
| random bytes | `rand_min`, `rand_max`, optional `rand_range_min`/`rand_range_max` (byte value window) |
| segments | `segments`: `bytes` (`bytes` hex), `random`/`random_ascii`/`random_digit` (`min_size`, `max_size`), `timestamp` (4 B), `counter` (4 B, per socket), `nonce` (8 B) |

Every item also takes `delay_min`/`delay_max` (ms) applied after it is sent.

Limits and behaviour:

- Each packet is at most `size_cap` bytes (default 1200); delays at most 5000 ms; `reset_min <= reset_max`; at least one item.
- State is kept per peer, bounded by `max_peers` (default 4096) and expired after 10 idle minutes; beyond the bound peers pass through without noise.
- Items with a delay run in the background; real datagrams for that peer are queued (64 max, QUIC retransmits any dropped) and released in order after the train. Other peers are never blocked.
- Server side only: noise towards a peer is limited to `amp_cap` times the bytes received from it (default 0.5), so a spoofed or junk packet cannot trigger a large reply. Together with QUIC's own 3x handshake limit the worst case is roughly 3.5x; lower `amp_cap` to tighten it.
- The wrapper keeps quic-go's batched reads, ECN and GSO paths when the socket is a `*net.UDPConn`.
