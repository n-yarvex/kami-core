# vless-ws and vless-xudp

Two plugins in one package. Both speak the VLESS request header (version 0, no addons, `flow` is not supported)
and carry UDP as Mux.Cool / XUDP frames, so `vless-ws` and the TLS flavour of `vless-xudp` are wire-compatible with
Xray / sing-box in their XUDP mode. The DTLS flavour is kami-specific (see below).

User ids are UUIDs, or any string of at most 30 bytes, which is mapped the way Xray does it (UUIDv5 with the zero namespace).

## vless-ws

Inbound (`"type": "vless-ws"`):

| key | meaning |
|---|---|
| `users` | `[{ "name": "alice", "id": "<uuid or string>" }]`, required |
| `path` | WebSocket path, default `/`; everything else gets 404 |
| `tls` | optional, same keys as the other inbounds (`certificate`, `key`, `self_signed`, `alpn`, …); omit it behind a CDN or reverse proxy |
| `handshake_timeout` | default `15s` |
| `xudp_hold` | how long UDP upstream sessions with an XUDP GlobalID survive a dropped connection, default `60s` |
| `disable_udp` | refuse the Mux.Cool command |

Early data (`Sec-WebSocket-Protocol` carrying base64url) is always accepted.

Outbound (`"type": "vless-ws"`):

| key | meaning |
|---|---|
| `server`, `id` | required |
| `path`, `host`, `headers` | WebSocket request path, `Host` header (default: `tls.server_name`, else the server host), extra headers |
| `tls` | enables `wss`. Same keys as the other outbounds plus `fingerprint` (uTLS) |
| `early_data` | 0-8192 bytes of the first write sent inside the upgrade request; `0` disables |
| `early_data_header` | default `Sec-WebSocket-Protocol` |
| `ping_interval` | WebSocket ping, default `30s`, `"0s"` disables |
| `udp` | default `true`; UDP uses one XUDP session per `OpenPacket` |
| `xudp_keepalive` | XUDP keep-alive frame interval, default `20s` |

`tls.fingerprint` values: `chrome`, `firefox`, `safari`, `ios`, `android`, `edge`, `360`, `qq`, `random`,
`random_no_alpn`, `random_full`, and pinned versions such as `chrome_120`, `firefox_105` (the full list is printed in the error
for an unknown name). Empty or `go` uses crypto/tls. The ALPN is forced to `http/1.1` because the transport is a
WebSocket upgrade. `ech_config` cannot be combined with a fingerprint.

## vless-xudp

UDP only. `transport` selects the layer under the VLESS/XUDP stream: `tls` (default) or `dtls`.

Inbound:

```json
{ "type": "vless-xudp", "tag": "xudp-in", "listen": "0.0.0.0:4443",
  "transport": "dtls",
  "users": [{ "name": "alice", "id": "5783a3e7-e373-51cd-8642-c83782b807c5" }],
  "dtls": { "certificate": "cert.pem", "key": "key.pem", "client_auth": "none" },
  "idle_timeout": "2m", "xudp_hold": "60s" }
```

With `"transport": "tls"` give a `tls` block instead (TCP listener). Exactly one of `tls` / `dtls` is accepted.

Outbound:

```json
{ "type": "vless-xudp", "tag": "xudp", "server": "203.0.113.5:4443",
  "id": "5783a3e7-e373-51cd-8642-c83782b807c5",
  "transport": "dtls",
  "dtls": { "pins": ["<sha256>"], "server_name": "example.com", "flight_interval": "500ms", "mtu": 1300 },
  "turn": { "server": "turn.example.net:3478", "transport": "udp", "username": "u", "password": "p", "realm": "example.net" },
  "keepalive": "20s" }
```

`dtls` options (client and server): `cipher_suites` (names such as `TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256`), `flight_interval`,
`mtu`, `extended_master_secret` (`request` / `require` / `disable`), `replay_window`, `handshake_timeout`, `psk`, `psk_identity`.
The client also takes every `tls` client key used for verification (`server_name`, `pins`, `ca`, `insecure`). The server takes
`certificate`/`key`/`self_signed`, `client_auth` (`none`, `request`, `require_any`, `verify_if_given`, `require_verify`) and `client_ca`.
With `psk` set the handshake is PSK-only (default suites: ECDHE-PSK-ChaCha20-Poly1305, PSK-AES-128-GCM, PSK-ChaCha20-Poly1305, PSK-AES-128-CCM).

`turn` (DTLS only) allocates a relay on a TURN server (RFC 8656, long-term credentials) and sends the DTLS datagrams
to the server through it: `server`, `transport` (`udp`, `tcp`, `tls`), `username`, `password`, `realm`, `software`, `rto`, and `tls`
for `transport: "tls"`. The xudp server must be reachable from the TURN server's relay address.

### How it behaves

- One XUDP session per `OpenPacket`; every datagram carries its own destination, so a socket behaves as full cone.
- Each session has a random 8-byte GlobalID. If the connection drops, the client reconnects (backoff 1 s to 15 s) and
  the server re-attaches the same upstream session (valid for `xudp_hold`), so NAT bindings survive.
- DTLS framing is kami-specific: after the handshake the client sends a hello datagram (`0x01` + VLESS header, retransmitted
  every second until acknowledged by `0x02`), then every datagram is `0x03` + one or more frames. Losing a datagram loses only
  that packet. Xray has no DTLS transport, so the DTLS mode only works kami-to-kami.
- Client keep-alive frames are echoed by kami servers; the DTLS client treats three missed intervals as a dead link.

### Limits

- TCP sessions inside Mux.Cool are refused (`End` with error); use `vless-ws` for TCP. `flow` (Vision) is not implemented.
- The TURN client does not authenticate the XUDP server with anything but DTLS: use `pins`, `ca` or a PSK.
- DTLS client certificates are not sent (server-side `client_auth` exists, but there is no client certificate option yet).
- Not tested against a real Xray binary (it needs Go 1.27 and was not buildable here); the frame layout follows its source.
