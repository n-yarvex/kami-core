# masque

HTTP/3 proxy, inbound and outbound: plain `CONNECT` for TCP (RFC 9114 §4.4) and `CONNECT-UDP` (RFC 9298)
with HTTP Datagrams (RFC 9297). Built on quic-go's `http3` package.
Verified against `quic-go/masque-go` (its client against our inbound, our outbound against its `Proxy`)
and against quic-go's own HTTP/3 `CONNECT` client and server, see `interop/masque`.

## Scope

- Done: CONNECT (TCP), CONNECT-UDP, datagram transport with capsule fallback, authentication, cover responses.
- Not done: CONNECT-IP (RFC 9484), and the optional HTTP/2-over-TCP listener. Nothing here pretends otherwise.

## Behaviour worth knowing

- One long-lived QUIC connection per outbound. When the server's stream limit is hit another connection is opened
  (up to 8). Reconnects are de-duplicated and back off from 200 ms to 5 s.
- TCP: `DialStream` waits for the proxy's answer before returning, so failures reach the router as errors:
  `407` -> `ErrAuthRequired`, `403` -> `ErrForbidden`, `502/503/504` -> `ErrUpstream`, anything else a `*StatusError`
  (unwrap with `errors.As`). This costs one round trip; no data is sent optimistically.
- UDP: RFC 9298 ties one request stream to one target. A packet connection from the router may talk to many peers, so
  the outbound opens one CONNECT-UDP stream per peer on demand (at most 64 per flow, least recently used is dropped)
  and merges replies. Each datagram carries context ID 0.
- Datagrams are used when both sides negotiated them. A payload that does not fit a QUIC datagram is sent as a DATAGRAM capsule
  on the request stream (reliable, ordered, subject to flow control). Incoming datagrams and capsules are both accepted.
  `no_datagram` forces capsules for sending.
- The inbound never answers unauthenticated or non-proxy requests with a proxy-specific status. Wrong credentials, missing
  credentials, plain `GET`s, wrong paths and unknown `:protocol` values all get the same configurable cover response
  (default `404`). Set `challenge: true` to answer `407` + `Proxy-Authenticate` instead.
- Credentials are compared in constant time across all users. At least one user is required: there is no open-proxy mode.
- A CONNECT-UDP target that is a domain is resolved by the router, once per stream.

## Options

Outbound:

```json
{
  "type": "masque",
  "server": "203.0.113.5:443",
  "authority": "proxy.example.com",
  "auth": { "user": "ann", "password": "change-me" },
  "headers": { "User-Agent": "curl/8.5.0" },
  "tls": { "server_name": "proxy.example.com", "pins": ["hex sha256 of the certificate public key"] },
  "udp_template": "/.well-known/masque/udp/{target_host}/{target_port}/",
  "udp_timeout": "3m",
  "disable_udp": false,
  "no_datagram": false,
  "keepalive": "10s",
  "idle_timeout": "30s",
  "stream_window_mib": 8,
  "conn_window_mib": 20
}
```

`auth` takes either `user`/`password` (Basic) or `token` (Bearer). `authority` overrides the `:authority` sent to the proxy
(default is `server`).

Inbound:

```json
{
  "type": "masque",
  "listen": ":443",
  "users": [ { "name": "ann", "password": "change-me" }, { "name": "robot", "token": "long-random-token" } ],
  "tls": { "certificate": "/etc/kami/fullchain.pem", "key": "/etc/kami/key.pem" },
  "path": "/.well-known/masque/udp/{target_host}/{target_port}/",
  "fallback": { "status": 404, "body": "404 page not found\n", "content_type": "text/plain; charset=utf-8", "headers": { "Server": "nginx" } },
  "challenge": false,
  "max_streams": 1024,
  "udp_timeout": "4m",
  "disable_udp": false
}
```

Templates must contain `{target_host}` and `{target_port}` once each and may use either the path or the query.
IPv6 literals are percent-encoded on the wire (`2001%3Adb8%3A%3A1`); bracketed forms are accepted when parsing.
