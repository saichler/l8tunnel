# l8tunnel: Product Requirements Document

| | |
|---|---|
| **Status** | Draft v0.1 |
| **Owner** | Sharon Aicler |
| **Date** | 2026-09-24 |
| **Language** | Go |
| **Coding guidelines** | `../l8book/layer-8-guide-lines.md` (only the generic Go/engineering rules apply, see §13) |

---

## 1. Summary

l8tunnel is a self-hosted reverse-tunnel service, similar to ngrok. It lets you reach SSH servers and web applications that sit behind NAT or a firewall that blocks inbound connections. A small **agent** runs next to the private service and opens an outbound connection to a **relay server** on a machine with a public IP. The relay accepts public traffic (HTTPS and SSH) and forwards it back through the agent's connection to the private service.

Nothing has to open on the private network. The agent only makes outbound connections, over a port that is almost always allowed (TCP 443).

## 2. Problem statement

- Machines on home or office networks, in labs, or behind carrier-grade NAT can't take inbound connections.
- Hosted services like ngrok, Cloudflare Tunnel and Tailscale Funnel send traffic through a third party. They can cost money per tunnel or per custom domain, and they limit protocols or bandwidth.
- The owner already has a machine with a public IP and wants a simple way to use it as a relay, under their own control, with their own domain.

## 3. Goals

1. **Expose HTTPS services** behind a firewall at a public hostname, for example `app1.tunnel.example.com`.
2. **Expose SSH** behind a firewall so a standard `ssh` client can reach it with little or no special setup.
3. **Outbound-only agent.** The agent needs only outbound TCP 443 and survives network interruptions by reconnecting on its own.
4. **Secure by default.** All traffic between agent and relay uses TLS. Agents authenticate. Tunnels can require authentication from public users.
5. **Simple operations.** One static binary each for the server and the agent, a YAML config, automatic TLS certificates, and a systemd-friendly setup.

## 4. Non-goals (v1)

- A multi-tenant SaaS with sign-up, billing or a web dashboard for strangers.
- Multi-region, anycast or relay clustering.
- UDP tunnels (games, DNS, WireGuard). Possible later.
- A full VPN or mesh network. l8tunnel exposes individual services, not whole networks.
- Replacing SSH authentication. l8tunnel carries SSH bytes and does not terminate SSH.

## 5. Users and use cases

| Persona | Use case |
|---|---|
| **Homelab owner** | SSH into a home server from anywhere. Expose a Home Assistant or Grafana UI over HTTPS. |
| **Developer** | Share a local dev server (`localhost:3000`) with a colleague or a webhook provider (GitHub, Stripe) under a stable URL. |
| **Field/edge ops** | Reach devices on customer sites (behind strict firewalls) over SSH for support. |
| **Small team admin** | Give a few teammates their own agents and tunnels on a shared relay, each with separate tokens. |

### Key user stories

- *As an operator*, I install `l8tunnel-server` on my public VM, point `*.tunnel.example.com` at it, and it gets TLS certificates on its own.
- *As a user*, I run `l8tunnel-agent --token XXX http 8080 --name myapp` and `https://myapp.tunnel.example.com` goes live within seconds.
- *As a user*, I run `l8tunnel-agent ssh --name homebox` and can then `ssh homebox.tunnel.example.com` (see §7.3 for how SSH gets routed).
- *As a user*, I protect a tunnel with basic auth, OAuth/OIDC or an IP allowlist, so only I can reach an internal admin UI.
- *As an operator*, I can list the active agents and tunnels, revoke a token, and see traffic stats.

## 6. System overview

```
                 Public Internet                       │   Private network (behind NAT/firewall)
                                                       │
  Browser ──HTTPS──┐                                   │
                   ▼                                   │
  ssh client ──► ┌─────────────────────────────┐       │      ┌──────────────────┐     ┌──────────────┐
                 │   l8tunnel-server (relay)    │◄──────┼──────│  l8tunnel-agent  │────►│ local service│
                 │  - public listeners :443/:22 │  TLS  │      │  (outbound only) │     │ :8080 / :22  │
                 │  - router (SNI/Host/port)    │ mux'd │      └──────────────────┘     └──────────────┘
                 │  - control plane + auth      │ conn  │
                 │  - ACME cert manager         │       │
                 └─────────────────────────────┘       │
```

### Components

1. **l8tunnel-server (relay):** runs on the public host.
   - Public listeners: `:443` (HTTPS plus the agent control channel), `:80` (ACME HTTP-01 challenges and redirect to HTTPS), and optionally `:22xx` or a port range for raw TCP/SSH.
   - **Router:** maps each incoming connection to a tunnel by TLS SNI, HTTP `Host` header or listening port.
   - **Control plane:** authenticates agents, registers tunnels, allocates hostnames and ports.
   - **Cert manager:** wildcard or per-host certificates through ACME (Let's Encrypt).
   - **Admin API/CLI:** a local Unix socket or an authenticated HTTPS endpoint.
2. **l8tunnel-agent:** runs inside the private network.
   - Keeps a persistent, multiplexed TLS session to the relay.
   - For each stream the relay opens, dials the configured local target (`127.0.0.1:8080`, `10.0.0.5:22`, and so on) and pipes bytes both ways.
   - Reconnects with exponential backoff and jitter, and re-registers its tunnels after a reconnect.
3. **l8tunnel (client helper, optional):** used on the *accessing* side for SSH routing over 443 (`ProxyCommand`, see §7.3).

## 7. Functional requirements

### 7.1 Agent ↔ relay control channel

| ID | Requirement |
|---|---|
| C-1 | The agent connects to `relay:443` over TLS 1.3. The relay tells control connections apart from public HTTPS by SNI (for example `connect.tunnel.example.com`) and/or ALPN (`l8tunnel/1`). |
| C-2 | Streams are multiplexed over the single TLS connection (for example with [yamux](https://github.com/hashicorp/yamux) or smux). Each public connection maps to one stream. |
| C-3 | The agent authenticates with a bearer token (v1). mTLS with agent certificates is optional in v1.1. |
| C-4 | The agent sends a `Register` message listing the tunnels it wants: type (http, tls, tcp/ssh), requested name, local target and options. The relay replies with the assigned public endpoints or errors (name taken, not authorized). |
| C-5 | Heartbeats every 15s (configurable on the relay, sent to the agent in `Welcome`). The agent sends `Ping`, the relay answers `Pong`. Either side drops the session after 3 missed intervals; the relay then parks the session's tunnels (see C-6). |
| C-6 | Reconnect with exponential backoff (1s → 60s cap, ±20% jitter), reset after every session that registered. Relay-assigned names are requested again on reconnect. A disconnected session's names and ports are held for the same token for a grace period (default 5 min), so URLs and ports stay stable across reconnects. An agent reconnecting with the same agent ID takes over its previous session's tunnels even if the relay hasn't detected that session as dead yet. Errors returned by the relay (bad token, name taken, invalid request) are not retried: the agent exits with the error. |
| C-7 | **WebSocket transport:** for networks that only allow HTTP(S), the agent can carry the control session over WebSocket (`transport: wss`): TLS to the control SNI with ALPN `http/1.1`, then an upgrade on `/l8tunnel/ws`, carrying the same multiplexed session. The transport is chosen explicitly in config; the agent never switches silently. Both transports, and `l8tunnel connect`, go through HTTP CONNECT proxies: an explicit `proxy: http://user:pass@host:port`, `none`, or by default `HTTPS_PROXY`/`NO_PROXY` (loopback addresses are never proxied through the environment). A proxy refusal is reported with its status, without leaking credentials. |
| C-8 | The protocol is versioned. The relay rejects incompatible agent versions with a clear error. |

### 7.2 HTTPS tunnels

| ID | Requirement |
|---|---|
| H-1 | Each HTTP tunnel gets a hostname `<name>.<base-domain>`. Names are user-chosen (if allowed and free) or randomly generated. |
| H-2 | **Termination mode (default):** the relay terminates TLS with its wildcard certificate (h2 and http/1.1, TLS 1.2+), routes by `Host` header, and forwards HTTP/1.1 to the agent over a stream. The `Host` must name the same tunnel as the TLS SNI, or the relay answers 421 Misdirected Request. The agent forwards to the local target over HTTP, or over HTTPS for an `https://` target (it speaks the TLS itself), with optional `insecure_skip_verify` for self-signed local services, which logs a warning at startup. This enables auth, header injection, logging and request inspection. |
| H-3 | **Passthrough mode** (tunnel type `tls`): the relay reads the ClientHello without consuming it, routes by SNI, and forwards the raw TLS bytes. The private service holds its own certificate, so encryption is end-to-end. The relay adds no L7 features in this mode. |
| H-4 | WebSockets, HTTP/2 (to the client), server-sent events, long polling and large uploads/downloads (streaming, no full buffering) are supported. |
| H-5 | The relay adds `X-Forwarded-For`, `X-Forwarded-Proto` and `X-Forwarded-Host` headers (`forwarded_headers`, default on). Incoming `X-Forwarded-*` headers from clients are always dropped, so they can't be spoofed. |
| H-6 | **Custom domains:** a user can map `app.mydomain.com` (a CNAME to the relay) to a tunnel. The relay gets a certificate for it through HTTP-01 or TLS-ALPN-01. |
| H-7 | **Access control per tunnel**, declared in the agent's tunnel config and enforced by the relay: IP `allow_ips`/`deny_ips` (addresses or CIDRs, deny wins; every tunnel type, both modes; HTTP gets a 403 page, other types are refused) and HTTP `basic_auth` users with bcrypt hashes (`l8tunnel hash-password`; `$2a$`/`$2b$`/`$2y$` accepted). Verified credentials skip bcrypt for 5 minutes (digest cache), and the `Authorization` header is removed before the request reaches the service. OIDC is v1.1. |
| H-8 | Port 80 (`listen.http`, `off` disables it) redirects to HTTPS with 308, except ACME HTTP-01 challenge paths. |
| H-9 | A friendly HTML error page (plus an `X-L8tunnel-Error` header) when a tunnel exists but the agent is offline (502 `agent-offline`), the service behind the agent doesn't answer (502 `upstream-error`), or the name is unknown (404 `tunnel-not-found`). Clients other than `l8tunnel connect` get the page for any `<name>.<base-domain>`. In `acme.mode: http01` an unreserved name has no certificate, so the handshake fails instead. |

### 7.3 SSH tunnels

SSH carries no hostname (no SNI or Host header), so routing needs a different approach. l8tunnel supports three modes. v1 ships modes A and B.

| Mode | How the user connects | Pros | Cons |
|---|---|---|---|
| **A. Dedicated port** | `ssh -p 22001 user@tunnel.example.com` | Zero client setup. Any SSH client works. | Uses one public port per tunnel. Some networks block uncommon ports. |
| **B. SNI over TLS (ProxyCommand)** | `~/.ssh/config`: `ProxyCommand l8tunnel connect %h` → `ssh homebox.tunnel.example.com` | Everything goes over port 443 and gets past strict egress firewalls. One port for everything. | Needs the small `l8tunnel` helper on the client (or `openssl s_client` as a fallback). |
| **C. SSH jump gateway** (v1.1) | `ssh -J gw@tunnel.example.com user@homebox` | Standard OpenSSH `-J`. No extra binary. | The relay runs an SSH server; it needs gateway keys and user management. |

| ID | Requirement |
|---|---|
| S-1 | **Mode A:** the relay allocates a TCP port from a configured range (for example 22000–22999) or a requested fixed port. The mapping stays stable per tunnel name and token. |
| S-2 | **Mode B:** the relay accepts TLS on :443 with SNI `<name>.<base-domain>`. For tunnels of type `tcp`/`ssh`, it terminates the outer TLS and forwards the plain inner byte stream (the SSH protocol) to the agent. `l8tunnel connect` offers the ALPN `l8tunnel-connect/1`; for a name with no active tunnel, or the control SNI without the l8tunnel ALPN, its handshake fails, so it gets an error instead of an empty connection or an HTML page. The name `connect` (the control SNI's label) can't be used as a tunnel name. |
| S-3 | `l8tunnel connect <host>` opens TLS to the relay with the given SNI and pipes stdin/stdout, so it works as an OpenSSH `ProxyCommand`. |
| S-4 | The relay never sees SSH credentials or plaintext, because SSH encrypts end to end. The relay only carries bytes. |
| S-5 | IP allow/deny lists per tunnel (mode A and B). Optional `access_token` per TCP/SSH tunnel: only its SHA-256 goes to the relay; mode B clients must present it (`l8tunnel connect --access-token`, negotiated through the `l8tunnel-connect-token/1` ALPN and acknowledged by the relay, so a wrong token is an explicit error). A tunnel with an access token gets no mode A port, since raw TCP can't carry the token. Failed tokens count against the per-IP auth-failure limit. |
| S-6 | Generic raw TCP (for example RDP, VNC, databases) uses the same mechanism as SSH. SSH is just a TCP tunnel with a default local port of 22. |

### 7.4 Agent configuration and CLI

Quick start:
```bash
l8tunnel-agent --relay connect.tunnel.example.com:443 --token $TOKEN http 8080 --name myapp   # P2
l8tunnel-agent --relay connect.tunnel.example.com:443 --token $TOKEN ssh --name homebox      # local :22
l8tunnel-agent --relay connect.tunnel.example.com:443 --token $TOKEN tcp 5432 --name db --port 25432
l8tunnel-agent --config /etc/l8tunnel/agent.yaml
```

Config file (`/etc/l8tunnel/agent.yaml`):
```yaml
relay: connect.tunnel.example.com:443
token: ${L8TUNNEL_TOKEN}
status_socket: /run/l8tunnel-agent/status.sock
tunnels:
  - name: myapp
    type: http            # http | tls (passthrough) | tcp | ssh
    target: 127.0.0.1:8080   # or https://host:port (+ insecure_skip_verify)
    basic_auth:
      - { user: admin, password_hash: "$2y$..." }   # l8tunnel hash-password
  - name: homebox
    type: ssh
    target: 127.0.0.1:22
    public_port: 22001    # mode A; mode B is always available through SNI
    allow_ips: ["203.0.113.0/24"]
  - name: backup
    type: ssh
    access_token: ${BACKUP_TOKEN}   # mode B only: l8tunnel connect --access-token
```

| ID | Requirement |
|---|---|
| A-1 | CLI flags for one-off tunnels. A YAML config for persistent multi-tunnel setups. The two can't be mixed. YAML parsing is strict: unknown keys are errors. A value written as `${VAR}` is read from the environment, and an unset variable is an error. The token defaults to `$L8TUNNEL_TOKEN`. The server is configured only through its YAML file (`l8tunnel-server --config`). |
| A-2 | Runs as a systemd service. Ships unit files for the agent and the server (`deploy/systemd/`, the server binds :443 through `CAP_NET_BIND_SERVICE`, not root) and example configs (`deploy/examples/`), which a test keeps parseable. |
| A-3 | Prints the assigned public URL or port at startup and logs connect/disconnect events. |
| A-4 | Target can be any reachable host:port, not only localhost, so a single agent can expose multiple LAN hosts. |
| A-5 | `status_socket` (Unix socket, mode 0600) serves `l8tunnel-agent status [--socket] [--json]`: connection state, last error, reconnect count, and per-tunnel target, public address, connections and bytes. |

### 7.5 Server configuration and administration

```yaml
# /etc/l8tunnel/server.yaml (full example: deploy/examples/server.yaml)
base_domain: tunnel.example.com
control_sni: connect.tunnel.example.com   # default: connect.<base_domain>
listen:
  https: ":443"
  http: ":80"                             # "off" disables it
tcp_port_range: "22000-22999"
acme:                                     # or tls: {cert, key}
  mode: dns01                             # or http01
  email: admin@example.com
  dns_provider: cloudflare
  dns_credentials: {api_token: ${CF_API_TOKEN}}
storage: /var/lib/l8tunnel                # l8tunnel.db (tokens, reservations) and acme/
admin:
  socket: /run/l8tunnel/admin.sock
rate_limits: {connections_per_second: 20, connections_burst: 100, auth_failures_per_minute: 5}
```

| ID | Requirement |
|---|---|
| V-1 | Certificates come from exactly one of `tls` (static files) or `acme`. `acme.mode: dns01` gets a wildcard `*.base_domain` through a DNS provider API (pluggable through libdns; `cloudflare` first). `acme.mode: http01` gets the control host's certificate at startup and each tunnel host's on its first connection, but only for reserved tunnel names, so strangers can't make the relay order certificates for arbitrary names. Certificates needed at startup are obtained synchronously. Every misconfiguration (missing email, unknown provider, missing or misspelled credential, http01 without a fixed `listen.http` port, unreadable `ca_root`) stops the server before any network access and names the setting. Certificates are stored (`acme.storage`) and renewed automatically. `acme.ca` and `acme.ca_root` allow a private ACME CA. |
| V-2 | Token management through the admin socket: `l8tunnel-server token create --name laptop [--names ...] [--types ...] [--max-tunnels N] [--ports A-B]` (the token, `l8t_<id>_<secret>`, is printed once), `token list` (never secrets), `token revoke NAME`. Revoking deletes the token and its reservations and disconnects its sessions immediately; the agent then exits with UNAUTHORIZED instead of retrying. |
| V-3 | Policies per token, enforced at registration with ERROR_CODE_FORBIDDEN: allowed name patterns (`path.Match`, relay-assigned names included), allowed tunnel types, maximum connected tunnels (parked ones don't count), and an allowed tcp/ssh port range that narrows allocation. |
| V-4 | Permanent reservations: `l8tunnel-server reservation add --name N --token T [--port P]`, `list`, `remove`. A reserved name (and port) belongs to that token indefinitely, survives relay restarts, and is never released by the grace period. |
| V-5 | `l8tunnel-server status [--json]`: connected agents (token, agent ID, remote address, version, OS/arch, uptime), their tunnels (public address, active/total connections, bytes in/out), and parked names (grace expiry or reserved). |
| V-6 | Tokens and reservations live in an embedded bbolt database (`<storage>/l8tunnel.db`, pure Go, no external service). A second relay on the same database fails at once with a clear lock error. The admin API is HTTP on a Unix socket (`admin.socket`, mode 0600, stale sockets replaced, over-long paths rejected with a clear error). |

### 7.6 Observability

| ID | Requirement |
|---|---|
| O-1 | Structured logs (`log: {format: text\|json, level: debug\|info\|warn\|error}`, agent flags `--log-format`/`--log-level`): agent sessions, tunnel registrations, auth failures, and one line per public connection with client address, tunnel, duration and bytes. |
| O-2 | Prometheus metrics on `metrics.listen` (plain HTTP, text format, no client library): build info, connected agents, agent sessions total, per-agent heartbeat RTT (reported by the agent in each Ping), tunnels by type, parked names, per-tunnel active/total connections and bytes in/out, auth failures, and connections rejected by reason (rate_limit, ip_denied, no_route). |
| O-3 | Optional HTTP access log (`access_log: true`, relay-wide rather than per tunnel): host, method, path, protocol, status, bytes, duration, client, user agent and the relay's error reason, one line per request. |
| O-4 | Optional (v1.1): request inspection/replay for HTTP tunnels, like ngrok's inspector, exposed on the agent's local UI. |

## 8. Non-functional requirements

| Area | Requirement |
|---|---|
| **Security** | TLS 1.3 only on the control channel. Agent tokens are `l8t_<id>_<secret>`, looked up by ID with only a bcrypt hash of the secret stored. Per-IP rate limits on new connections (token bucket) and on failed agent/access-token authentications (an IP over its budget is refused until it refills). The relay binds :80/:443 through `CAP_NET_BIND_SERVICE` under systemd, not root. No tunnel is reachable before auth completes. The agent dials only its own configured targets: the relay only ever names a tunnel ID. |
| **Performance** | Adds at most 5 ms of latency in the relay (excluding network RTT). At least 500 Mbps aggregate throughput on a 2 vCPU VM. At least 1,000 concurrent public connections and at least 100 agents per relay. |
| **Reliability** | The agent survives relay restarts and network changes (Wi-Fi ↔ LTE). Reconnect and re-registration finish in under 5s once the network is back. The relay shuts down gracefully and drains connections. |
| **Resource use** | Idle agent under 20 MB RSS and near-zero CPU. |
| **Portability** | The agent runs on Linux (amd64, arm64, armv7 for Raspberry Pi), macOS and Windows. The server runs on Linux. |
| **Distribution** | Static Go binaries (`build.sh`: Linux amd64/arm64/armv7, macOS amd64/arm64, Windows amd64/arm64; the relay is Linux only), multi-stage Docker images (`--target server` / `--target agent`, distroless, non-root, about 30 MB), and systemd units. Installation must not require root beyond binding ports. |
| **Backpressure** | Per-stream flow control, so one slow client can't stall other streams on the same agent session. |
| **Fail fast** | Invalid or incomplete config makes the binary exit non-zero with a message naming the problem. A tunnel whose access policy can't be loaded is rejected at registration and never exposed without it. No silent degraded modes (see §13.2). |

## 9. Protocol sketch

1. The agent opens TCP to `relay:443` → TLS handshake with SNI `connect.<base>` and ALPN `l8tunnel/1`.
2. The multiplexer session starts. Stream 0 is the **control stream**, carrying length-prefixed **protobuf** messages defined in `proto/l8tunnel.proto` (see §13.3).
3. `Hello{version, token, agent_id, os, arch}` → `Welcome{session_id, heartbeat_interval}` or `Error`.
4. `Register{tunnels[]}` → `Registered{endpoints[]}`. Tunnels can be added or removed at runtime.
5. For each public connection, the relay opens a new stream to the agent with a header `StreamOpen{tunnel_id, client_addr, proto}`. The agent dials the target and pipes bytes both ways until either side closes. Half-close is supported.
6. `Ping`/`Pong` on the control stream serve as heartbeats and RTT measurement.

HTTP in termination mode is forwarded as a raw HTTP/1.1 byte stream per client connection. The relay converts HTTP/2 from the client to HTTP/1.1 toward the agent, or forwards h2c if the target supports it.

## 10. Phases and traceability

### 10.1 Phases

| Phase | Scope |
|---|---|
| **P0: Skeleton** | Repo layout per §13.1 (including the `go/vendor/` fix to `.gitignore`), `proto/l8tunnel.proto` and `make-bindings.sh`, mux session over TLS, token auth, one static TCP tunnel end to end, `go/tests/` end-to-end harness. |
| **P1: SSH MVP** | Mode A (port allocation) and mode B (SNI + `l8tunnel connect`), heartbeats, reconnect/backoff, YAML config, systemd units. *At this point you can SSH into a machine behind a firewall.* |
| **P2: HTTPS MVP** | Wildcard ACME (DNS-01) and explicit HTTP-01 mode, SNI/Host routing, termination and passthrough modes, WebSockets, error pages, X-Forwarded-* headers. |
| **P3: Security & admin** | Token CLI/policies, name reservations, basic auth, IP allowlists, SSH tunnel access tokens, rate limiting, hashed token storage, admin socket, status commands. |
| **P4: Ops polish** | Prometheus metrics, structured logs, access logs, Docker image, WebSocket transport, cross-platform builds, docs. |
| **P5: Final verification** | See §10.3. v1 isn't done until P5 passes. |
| **v1.1** | OIDC auth, custom domains, SSH jump gateway (mode C), mTLS agents, HTTP request inspector. |

### 10.2 Traceability matrix

Every requirement maps to exactly one phase. Platforms: **Server** = Linux; **Agent** and **Client** = Linux (amd64/arm64/armv7), macOS, Windows.

| # | Requirement(s) | Area | Platform | Phase |
|---|---|---|---|---|
| 1 | C-1, C-2, C-3, C-4, C-8 | Control channel: TLS, mux, token auth, register, versioning | Server, Agent | P0 |
| 2 | Backpressure NFR | Per-stream flow control | Server, Agent | P0 |
| 3 | §13.1, §13.3 | Repo layout, protobuf bindings, `.gitignore` vendor fix | All | P0 |
| 4 | C-5, C-6, Reliability NFR | Heartbeats, reconnect, name grace period | Server, Agent | P1 |
| 5 | S-1, S-2, S-3, S-4, S-6 | SSH/TCP modes A and B, `l8tunnel connect` | Server, Agent, Client | P1 |
| 6 | A-1, A-2, A-3, A-4 | Agent CLI, YAML, systemd, LAN targets | Agent | P1 |
| 7 | Fail-fast NFR | Config validation, no silent fallbacks | All | P1 (continued in every later phase) |
| 8 | H-1, H-2, H-3, H-4, H-5, H-8, H-9 | HTTPS routing, termination, passthrough, WebSockets, redirects, error pages | Server, Agent | P2 |
| 9 | V-1 | ACME certs (DNS-01, explicit HTTP-01) | Server | P2 |
| 10 | H-7 (basic auth, IP lists), S-5 | Per-tunnel access control | Server, Client | P3 |
| 11 | V-2, V-3, V-4, V-5, V-6 | Tokens, policies, reservations, status, storage | Server | P3 |
| 12 | A-5 | Agent status command | Agent | P3 |
| 13 | Security NFR | Hashing, rate limits, privilege drop, agent target allowlist | Server, Agent | P3 |
| 14 | C-7 | WebSocket transport, `HTTPS_PROXY` | Server, Agent | P4 |
| 15 | O-1, O-2, O-3 | Logs, metrics, access logs | Server, Agent | P4 |
| 16 | Portability, Distribution, Resource-use NFRs | Cross-builds, Docker image, systemd, memory footprint | All | P4 |
| 17 | Performance NFR, §11 metrics | Latency, throughput, concurrency benchmarks | Server, Agent | P5 |
| 18 | §13.2 coding rules | Compliance checks | All | P5 (enforced in every phase) |
| 19 | H-6, H-7 (OIDC), O-4, SSH mode C, mTLS (C-3) | Deferred features | Server, Agent | v1.1 |

### 10.3 Final verification (P5)

Results: [P5-verification.md](P5-verification.md).

Everything runs as end-to-end tests in `go/tests/`, against real relay and agent processes, using real clients (OpenSSH `ssh`, an HTTP client, a WebSocket client).

1. **SSH:** connect through mode A (dedicated port) and mode B (`ProxyCommand l8tunnel connect`). Check an interactive session, `scp` of a large file, and port forwarding over the tunnel.
2. **HTTPS:** termination mode (Host routing, X-Forwarded-* headers, WebSocket upgrade, a large streaming upload/download), passthrough mode (the certificate the client sees is the private service's), the 404/502 error pages, and the port 80 redirect.
3. **Resilience:** restart the relay, drop the agent's network, and confirm the agent reconnects in under 5s with the same public name.
4. **Security:** a revoked token disconnects immediately. Basic auth, IP allowlists and SSH access tokens are enforced. An invalid config makes the binary exit non-zero. A tunnel whose auth policy fails to load is never reachable.
5. **Platforms:** smoke-test the agent and client on Linux amd64, Linux arm64, macOS and Windows.
6. **Performance:** benchmark against the NFR targets (≤5 ms added latency, ≥500 Mbps, ≥1,000 concurrent connections, ≥100 agents, idle agent <20 MB RSS).
7. **Coding-rule compliance:** run every check in the §13.2 table. All must pass.
8. **Completeness:** walk this PRD section by section and confirm every requirement ID in §10.2 is implemented and covered by a test before calling v1 done.

## 11. Success metrics

- Time from a fresh VM to the first working HTTPS tunnel: **under 15 minutes** by following the README.
- Time from agent start to public URL live: **under 3 seconds**.
- Agent reconnects on its own after a relay restart or network change, with **zero manual action**, in over 99% of cases.
- SSH session through the tunnel feels no different from a direct connection (no added latency over 5 ms measured at the relay).

## 12. Risks and open questions

| # | Item | Notes / proposed direction |
|---|---|---|
| 1 | **Abuse/phishing** if the relay is ever opened to others | v1 is operator-issued tokens only, with no public sign-up. Add an interstitial warning page as an option. |
| 2 | **Wildcard cert needs DNS API access** | Offer `acme.mode: http01` (per-host certs on demand, rate limited by Let's Encrypt) as an explicit alternative the operator picks. No automatic downgrade (see V-1, §13.2). |
| 3 | **SSH over port 443** requires the helper binary | Document an `openssl s_client -quiet -connect relay:443 -servername %h` ProxyCommand as a zero-install alternative. |
| 4 | Mux library choice: yamux vs smux vs QUIC (quic-go) | Start with yamux over TLS/TCP (works everywhere). Evaluate QUIC later for head-of-line blocking and connection migration. |
| 5 | Should HTTP be forwarded as bytes or as parsed requests? | Bytes per connection in v1 (simpler, supports everything). Parsing is needed only for L7 features at the relay, which termination mode already does. |
| 6 | Storage: SQLite vs BoltDB | Prefer pure-Go (bbolt or modernc SQLite) to keep static binaries CGO-free. |
| 7 | IPv6 | Relay listeners should dual-stack by default. |

## 13. Engineering guidelines

l8tunnel follows the generic Go and engineering rules from `../l8book/layer-8-guide-lines.md`. It isn't a Layer 8 application, so the framework-specific rules don't apply (see §13.4).

### 13.1 Repository layout

```
l8tunnel/
├── plans/                         # PRDs and plans (this file)
├── proto/
│   ├── l8tunnel.proto             # control-protocol messages
│   └── make-bindings.sh           # the only way to generate Go bindings
└── go/
    ├── go.mod / go.sum
    ├── vendor/                    # never committed (.gitignore: go/vendor/)
    ├── types/l8tunnel/            # generated .pb.go, never hand-edited
    ├── cmd/
    │   ├── l8tunnel-server/main.go
    │   ├── l8tunnel-agent/main.go
    │   └── l8tunnel/main.go       # client helper (connect)
    ├── tunnel/
    │   ├── protocol/              # framing, message encode/decode
    │   ├── transport/             # TLS and WSS dialers/listeners, mux session
    │   ├── pipe/                  # the one bidirectional stream-copy implementation
    │   ├── relay/                 # public listeners, router (SNI/Host/port), session registry
    │   ├── agent/                 # agent session, reconnect, target dialer
    │   ├── httpproxy/             # termination mode: reverse proxy, headers, error pages
    │   ├── certs/                 # ACME (DNS-01 / HTTP-01)
    │   ├── auth/                  # tokens, basic auth, IP lists, rate limiting
    │   ├── store/                 # embedded DB (bbolt)
    │   ├── config/                # YAML loading and validation
    │   ├── admin/                 # admin socket and status
    │   └── metrics/               # Prometheus and structured logging
    └── tests/                     # all tests (end to end)
```

The current `.gitignore` has `# vendor/` commented out. P0 must replace it with an uncommented `go/vendor/` line.

### 13.2 Coding rules and compliance checks

| Rule | What it means for l8tunnel | Check (must pass) |
|---|---|---|
| **No Go generics** | No type parameters. Use interfaces or concrete types (for example `TunnelRegistry` with `*Tunnel` values, not `Registry[T]`). | `grep -rnE '(func\|type) [A-Za-z_]+\[[A-Za-z_]+ (any\|comparable\|interface)' go --include=*.go \| grep -v vendor/` returns nothing |
| **Minimal `main` package** | Each `cmd/*/main.go` only parses flags, loads config, builds components from `tunnel/...`, calls `Run`, and waits for a signal. No structs with methods, helpers or business logic. | Review: `main.go` files contain only `main()` and trivial wiring |
| **File size** | At most 500 lines per `.go` file. Split proactively at 450. Generated `go/types/` files are exempt. | `find go -name '*.go' -not -path '*/vendor/*' -not -path 'go/types/*' \| xargs wc -l \| awk '$2!="total" && $1>500'` returns nothing |
| **No duplication (second-instance rule)** | Extract a shared abstraction as soon as logic appears a second time. Concretely: one `pipe` implementation serves TCP, SSH, TLS passthrough and HTTP streams. SSH is a TCP tunnel preset, not separate code. All public listeners go through one router abstraction. | Review: no near-duplicate files that differ only in names or config |
| **Read before implementing** | Read the whole existing package (and the vendored library code in `go/vendor/`) before extending it or writing something similar. | Review |
| **Fail fast, no silent fallback** | Missing or invalid required config, certs or credentials → exit non-zero naming the problem. No automatic transport or ACME downgrade. No tunnel exposed without its configured auth. Errors are logged with their cause, never swallowed. Risky options such as `--insecure-skip-verify` are explicit opt-in and log a warning at startup. | P5 security tests (§10.3 item 4). Review: no ignored errors (`_ = err`, empty `if err != nil {}`) |
| **Report dependency bugs** | Bugs in dependencies (yamux, certmagic, and so on) are reported with what fails, expected vs actual and impact. They're fixed upstream, not worked around locally or by editing `vendor/`. | Review |
| **Test location and approach** | All tests live in `go/tests/`. No `_test.go` files next to source. Tests drive the system through its public surface (real TCP/TLS/SSH/HTTP connections to a real relay and agent), never unexported functions. | `find go -name '*_test.go' -not -path 'go/tests/*' -not -path '*/vendor/*'` returns nothing |
| **No stray binaries** | Use `go build ./...` or `go build -o /dev/null ./cmd/...`. Release builds write to an explicit output dir (`-o dist/...`), never the working directory. | `git status` shows no built binaries |
| **Vendor and git** | Never edit `go/vendor/`. `go/vendor/` is never committed. Module commands (`go mod init/tidy/vendor`) are run by the project owner, not by automation or AI assistants. Git commands only when instructed. | `git ls-files go/vendor \| head -1` returns nothing |
| **Plans** | Plans live in `./plans/`, include a traceability matrix and a final verification phase, and are approved before implementation starts. | This document (§10) |

### 13.3 Protobuf conventions

- Control-protocol messages (§9) are defined in `proto/l8tunnel.proto`, and Go bindings are generated only through `proto/make-bindings.sh` into `go/types/l8tunnel/`. Never compile individual proto files by hand. After any `.proto` change, rerun the script and `go build ./...`.
- Every enum's zero value is `<ENUM>_UNSPECIFIED = 0` and is never a valid state. The relay rejects messages that carry it. For example:

```protobuf
enum TunnelType {
  TUNNEL_TYPE_UNSPECIFIED = 0;
  TUNNEL_TYPE_HTTP = 1;   // termination mode
  TUNNEL_TYPE_TLS = 2;    // passthrough mode
  TUNNEL_TYPE_TCP = 3;
  TUNNEL_TYPE_SSH = 4;    // TCP preset, default target :22
}
```

- Check: `grep -A1 "^enum " proto/*.proto | grep "= 0" | grep -iv unspecified` returns nothing.

### 13.4 Rules that don't apply

These guideline rules are specific to the Layer 8 framework and are out of scope for l8tunnel: l8ui/UI and mobile rules, l8erp/probler project structure, ServiceName/ServiceArea and ServiceCallbacks, the ORM and single-owner tables, L8Query, `ISecurityProvider`/l8secure, the l8events/l8notify/log-vnet services, the 4-mode Kubernetes manifests and Layer 8 base images, `run-local.sh` with DB and mock data, and the Playwright/KIND browser E2E suite.

## 14. Glossary

- **Relay / server:** the public machine running `l8tunnel-server`.
- **Agent:** the process inside the private network that dials out to the relay.
- **Tunnel:** a mapping from a public endpoint (hostname or port) to a private target via an agent.
- **Termination vs passthrough:** whether the relay decrypts the public TLS (termination) or forwards encrypted bytes as-is (passthrough).
- **SNI:** Server Name Indication, the hostname sent in the clear in the TLS ClientHello. Used for routing without decrypting.
