# socks and http outbounds

## socks

```json
{ "type": "socks", "tag": "up", "server": "127.0.0.1:1080", "username": "u", "password": "p", "udp": true }
```

SOCKS5 with no-auth or username/password. `CONNECT` for TCP, `UDP ASSOCIATE` for UDP (the control TCP connection is
held open for the lifetime of the packet connection). `udp: false` disables UDP.

## http

```json
{ "type": "http", "tag": "up", "server": "proxy.example.com:443", "username": "u", "password": "p",
  "tls": { "server_name": "proxy.example.com", "fingerprint": "chrome", "pins": ["<sha256>"] },
  "headers": { "User-Agent": "Mozilla/5.0" } }
```

HTTP `CONNECT`, optionally over TLS (HTTPS proxy) with an optional uTLS `fingerprint` (ALPN `http/1.1`). No UDP.
`Host`, `Proxy-Authorization`, `Content-Length`, `Transfer-Encoding`, `Connection` and `Proxy-Connection` cannot be set in `headers`.

# http inbound over TLS

The `http` and `mixed` inbounds keep working as before; the `http` inbound additionally accepts `"tls": { "certificate": "…", "key": "…" }`
to serve an HTTPS proxy (ALPN defaults to `http/1.1`).
