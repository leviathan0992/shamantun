# shamantun

`shamantun` is a lightweight, secure TUN-to-Proxy client built in pure Go.
It captures system-wide traffic via a TUN interface and forwards it to remote
upstreams using encrypted tunnels.

## Features

- **TUN-to-Proxy**: Captures all system traffic via a Layer 3 TUN interface.
- **Protocol Support**: SOCKS5-over-TLS (TCP/UDP) and HTTPS CONNECT-over-TLS.
- **Generic UDP Relay**:
  - In `socks5tls` mode with `enable_udp=true`, forwards UDP traffic through
    SOCKS5 UDP Associate without protocol-specific port policy in the relay path.
- **DNS over TCP**:
  - DNS traffic (`udp/53`) is relayed through a proxied TCP exchange, while
    the rest of the UDP path remains generic.
- **Auto-Routing**: Can manage system routing tables for zero-config
  operation, and can also be disabled.
- **Pure Go Performance**: Built with the `gvisor` netstack and `sync.Pool`
  buffer management; no CGO or native library dependencies.

## Build and Deployment

### Build
Requires Go 1.21+
```bash
go build -o shamantun ./cmd/shamantun
```

### Run
```bash
# Basic run with configuration
sudo ./shamantun -c config.json
```

*Note: Root privileges are required to create and manage the TUN interface.*

## Configuration

```json
{
  "mode": "socks5tls",
  "upstream": "1.2.3.4:443",
  "client_pem": "client.pem",
  "client_key": "client.key",
  "username": "user",
  "password": "pass",
  "auto_route": true,
  "enable_udp": true,
  "insecure_skip_verify": false
}
```

### Key Parameters

- `mode`: Protocol for upstream communication (`socks5tls` or `https`).
- `upstream`: Remote proxy endpoint (`host:port`).
- `client_pem` / `client_key`: mTLS credentials (Required).
- `auto_route`: Automatically manage system routes. Default: `true`.
- `enable_udp`: Enables UDP relay (SOCKS5 mode only). Default: `false`.
- `insecure_skip_verify`: Disables upstream TLS certificate validation.
  Default: `false`. Only use for controlled testing.

## Network Behavior

- **DNS over TCP**: DNS queries (`udp/53`) are relayed through a proxied TCP exchange.
- **UDP Relay**: In `socks5tls` mode with `enable_udp=true`, UDP destinations
  are forwarded through the upstream SOCKS5 relay.
- **HTTPS Mode**: HTTPS CONNECT mode proxies TCP only. UDP is not forwarded in this mode.
- **Auto-Route Scope**: Linux and macOS auto-route manage both IPv4 and IPv6
  default routes when the host has active defaults for those families.

## License

MIT License. See the [LICENSE](LICENSE) file for details.
