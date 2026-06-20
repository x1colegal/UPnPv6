# UPnPv6

UPnPv6 is a Python NAT66 helper that opens and forwards IPv6 service ports, while using an IPv4 control channel to talk to the router.

The real forwarded service is IPv6. The client-to-router control connection uses TCP port `255` over IPv4.

## Features

- IPv4 control plane to the router on TCP `255`
- IPv6 target allocation for NAT66-style setups
- Optional `--gateway` override for the router IPv4 address
- Automatic IPv4 router scan across `192.168.0.1` to `192.168.255.254`
- Separate temporary challenge port for token validation
- Stable Base64 token per gateway, saved by both server and client
- Saved allocation list per gateway on the client
- `--unalocate-port` support for de-allocation with token authorization
- `TCP/255` rejection
- `iptables` and `nftables` backend support
- Optional `systemd` self-install

## Protocol

The control channel uses newline-delimited JSON over TCP `255` on IPv4.

### Allocate request

```json
{
  "action": "ALLOCATE",
  "req_port": 8080,
  "req_proto": "TCP",
  "local_ip": "fd42:dead:beef::1234",
  "challenge_port": 49152,
  "gateway_ip": "192.168.60.1",
  "client_ipv4": "192.168.60.44"
}
```

### Challenge

```json
{
  "status": "CHALLENGE",
  "token": "base64-token"
}
```

The server saves this token in its state file. The client also saves it locally. The same token is reused forever for the same gateway/local network identity, and only changes when the gateway changes.

### De-allocate request

```json
{
  "action": "UNALLOCATE",
  "req_port": 8080,
  "req_proto": "TCP",
  "gateway_ip": "192.168.60.1",
  "token": "base64-token"
}
```

This prevents another person on the same network from de-allocating a port they did not allocate, because they would also need the saved token.

## State files

- Server state: `~/.upnpv6_server_state.json`
- Client state: `~/.upnpv6_client_state.json`

The client file stores:

- token per gateway
- local IPv6 used with that gateway
- every allocated port saved in memory on disk

The server file stores:

- token history
- active allocations

## Running

### Start the server

```bash
sudo python3 upnpv6_server.py --listen 0.0.0.0 --port 255
```

At startup, the server asks which backend should be used and whether it should install itself as a `systemd` service.

### Allocate a port

```bash
python3 upnpv6_client.py --port 8080 --proto TCP
```

Optional gateway override:

```bash
python3 upnpv6_client.py --port 8080 --proto TCP --gateway 192.168.60.1
```

If `--gateway` is not provided, the client scans from `192.168.0.1` to `192.168.255.254` looking for TCP `255`.

### De-allocate a port

```bash
python3 upnpv6_client.py --unalocate-port 8080
```

Optional gateway override:

```bash
python3 upnpv6_client.py --unalocate-port 8080 --gateway 192.168.60.1
```

## Why use IPv4 for Control?

The forwarded destination is still IPv6, because the project is meant for NAT66-style IPv6 forwarding.

The control channel uses IPv4 because scanning private IPv6 space would take far too long in practice. I wanted the client to be able to scan private router addresses quickly, and scanning IPv4 ranges is much faster and much more practical than trying to brute-force private IPv6 addresses.

That is why the client scans IPv4 router candidates for the control server, while the actual forwarded target remains IPv6.

## Security model

1. The client talks to the router over IPv4 on TCP `255`.
2. The client asks for an IPv6 service port allocation.
3. The client opens a temporary IPv6 challenge port.
4. The server sends or reuses a Base64 token.
5. The server validates the token echo on the challenge port.
6. The server stores the token and allocation state.
7. The client stores the same token and its saved allocation list.
8. Later, de-allocation requires the stored token.

## Notes

- The control plane is IPv4-only.
- The forwarded destination is IPv6-only.
- `TCP/255` is always rejected with `ERROR=UPNPV6_PORT_CANT_BE_ALLOCATED`.
- `UDP/255` can still be allocated if it is free.

## Attribution

Made with GPT-5.4 (Low) using Codex (VSCode).
