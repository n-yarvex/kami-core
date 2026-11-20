# wireguard

Userspace WireGuard (`wireguard-go` device + a gVisor network stack). The UDP socket comes from kami's dialer/listener,
so `detour`, `bind_interface` and `routing_mark` apply to the outbound.

## Outbound (client)

```json
{ "type": "wireguard", "tag": "wg", "server": "203.0.113.5:51820",
  "private_key": "<base64>", "peer_public_key": "<base64>", "preshared_key": "<base64>",
  "local_address": ["10.8.0.2/32", "fd00::2/128"],
  "allowed_ips": ["0.0.0.0/0", "::/0"], "mtu": 1420, "reserved": [1, 2, 3],
  "keepalive": "25s" }
```

- Starts lazily on first use. Domain destinations are resolved by kami's resolver, then dialed through the tunnel by IP.
- TCP and UDP (full cone: one socket per address family you gave in `local_address`). `disable_udp` turns UDP off.
- `reserved` rewrites bytes 1-3 of every WireGuard packet (Cloudflare WARP style) and zeroes them on receive.
- Destinations in `127.0.0.0/8` cannot be dialed (the stack drops them as martians).

## Inbound (server)

```json
{ "type": "wireguard", "tag": "wg-in", "listen": "0.0.0.0:51820", "allow_private": false,
  "private_key": "<base64>", "mtu": 1420, "reserved": [1, 2, 3],
  "peers": [{ "name": "alice", "public_key": "<base64>", "preshared_key": "<base64>",
              "allowed_ips": ["10.8.0.2/32"], "keepalive": 25 }] }
```

Every TCP connection and UDP flow leaving the tunnel is handed to the router with the peer's `name` as `user`.
`kami gen key` prints a base64 32-byte value; a WireGuard key pair needs `wg genkey | tee priv | wg pubkey`.

### Limits

- UDP flows from the tunnel are per 5-tuple (not full cone), and replies are always sent from the destination the client
  asked for, even if another address answered.
- No ICMP forwarding: ping through the tunnel is not relayed.
- No hot peer changes: reload the config to add peers.
