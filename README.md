# l8tunnel

A self-hosted reverse tunnel, like ngrok, for a machine you control with a
public IP. Reach SSH servers and web applications behind NAT or a firewall:
a small **agent** next to the service connects *out* to your **relay**, and
the relay forwards public traffic back through that connection. Nothing
has to be opened on the private network.

```
 browser / ssh ──► l8tunnel-server (relay, public IP) ◄── TLS ── l8tunnel-agent ──► your service
                   :443  :80  :22000-22999                   (outbound only)       :8080 / :22
```

- **HTTPS tunnels:** `https://<name>.<base-domain>`, TLS terminated at the
  relay (HTTP/1.1, HTTP/2, WebSockets, streaming), or passed through
  untouched to a service that has its own certificate.
- **SSH and TCP tunnels:** a dedicated public port (`ssh -p 22001 ...`), or
  everything over port 443 with `ProxyCommand l8tunnel connect %h`.
- **Certificates:** your own files, or Let's Encrypt (wildcard through DNS,
  or per host through HTTP).
- **Access control:** per-agent tokens with policies, per-tunnel IP
  allow/deny lists, HTTP basic auth, SSH access tokens, per-IP rate limits.
- **Operations:** automatic reconnect, `status` commands, Prometheus
  metrics, JSON logs, systemd units, Docker images, static binaries for
  Linux, macOS and Windows.

## Quick start

### 1. DNS

Point `tunnel.example.com` and `*.tunnel.example.com` at the relay.

### 2. The relay

```bash
sudo install -m 755 l8tunnel-server /usr/local/bin/
sudo useradd --system --home /var/lib/l8tunnel l8tunnel
sudo install -d /etc/l8tunnel
sudo cp deploy/examples/server.yaml /etc/l8tunnel/   # edit base_domain and certificates
sudo cp deploy/systemd/l8tunnel-server.service /etc/systemd/system/
sudo systemctl enable --now l8tunnel-server
```

With `acme: {mode: dns01, ...}` the relay gets a wildcard certificate from
Let's Encrypt at startup (see `deploy/examples/server.yaml`). Every
misconfiguration stops the relay with a message naming the setting.

Create an agent token (it is printed once):

```bash
sudo l8tunnel-server token create --name laptop
```

### 3. The agent

```bash
export L8TUNNEL_TOKEN=l8t_...
l8tunnel-agent --relay connect.tunnel.example.com:443 http 3000 --name app
# -> https://app.tunnel.example.com

l8tunnel-agent --relay connect.tunnel.example.com:443 ssh --name homebox
# -> ssh -p <port> user@tunnel.example.com   (mode A)
# -> ssh -o ProxyCommand='l8tunnel connect %h' user@homebox.tunnel.example.com   (mode B)
```

For a permanent setup, use `deploy/examples/agent.yaml` and
`deploy/systemd/l8tunnel-agent.service`.

## Tunnel types

| Type | Public side | Notes |
|---|---|---|
| `http` | `https://<name>.<base>` | TLS terminated at the relay; `X-Forwarded-*` headers; basic auth; target may be `https://` (with `insecure_skip_verify` for self-signed services) |
| `tls` | `<name>.<base>:443` | Passthrough: the relay routes by SNI and never decrypts |
| `ssh` | port from `tcp_port_range`, and `<name>.<base>:443` via `l8tunnel connect` | Target defaults to `127.0.0.1:22` |
| `tcp` | same as `ssh` | Any TCP service (RDP, databases, ...) |

**Custom domains:** point `app.example.com` at the relay with a CNAME,
allow it on the token (`l8tunnel-server token create --name t --domains
'*.example.com'`), and add `domains: [app.example.com]` to an http or tls
tunnel. With ACME the relay gets its certificate on first use.

A disconnected agent's names and ports stay reserved for its token for 5
minutes, so URLs survive restarts; `l8tunnel-server reservation add` makes
that permanent.

## SSH from the client side

```
# ~/.ssh/config
Host *.tunnel.example.com
    ProxyCommand l8tunnel connect %h
```

Or, with no helper at all, through the relay's SSH jump gateway
(`ssh_gateway: {listen: ":2222"}` in `server.yaml`):

```bash
l8tunnel-server gateway-key add --name alice --key-file alice.pub --tunnels 'home*'
ssh -J gw@tunnel.example.com:2222 user@homebox
```

`l8tunnel connect` only needs outbound port 443 and honors `HTTPS_PROXY`.
Without it installed, `ProxyCommand openssl s_client -quiet -connect %h:443
-servername %h` works too (not for tunnels with an access token).

## Access control

On the relay, per token:

```bash
l8tunnel-server token create --name ci --names 'ci-*' --types http --max-tunnels 3
l8tunnel-server token revoke ci        # disconnects its agents immediately

# Client certificates instead of token strings (--require-cert makes them mandatory):
l8tunnel-server token create --name edge --require-cert
l8tunnel-server agent-cert issue --token edge --out edge   # edge.crt, edge.key
# agent: --cert edge.crt --key edge.key   (or cert:/key: in agent.yaml)
```

In the agent's config, per tunnel:

```yaml
tunnels:
  - name: grafana
    type: http
    target: 3000
    allow_ips: [203.0.113.0/24]
    basic_auth:
      - {user: admin, password_hash: "$2a$10$..."}   # l8tunnel hash-password
  - name: backup
    type: ssh
    access_token: ${BACKUP_TOKEN}   # clients: l8tunnel connect --access-token ...
  - name: wiki
    type: http
    target: 8080
    oidc: {provider: google, allow_domains: [example.com]}   # sign in with Google
```

For `oidc`, configure the provider on the relay (`oidc.providers` in
`server.yaml`) and register `https://auth.<base-domain>/callback` as its
redirect URI. The service receives the signed-in email in `X-L8tunnel-User`.

## Request inspector

`l8tunnel-agent --inspect 127.0.0.1:4040 http 3000` records the requests
reaching your HTTP tunnels. Open http://127.0.0.1:4040 to browse them
(headers, bodies up to 64 KiB, live updates) and replay any of them against
your local service. It binds loopback only unless `inspect_public: true`.

## Restricted networks

If only HTTP(S) through a proxy is allowed out, run the agent with
`transport: wss` (WebSocket over TLS). Both transports honor `HTTPS_PROXY`
and `NO_PROXY`, or an explicit `proxy: http://user:pass@proxy:3128`.
Loopback addresses are never proxied through the environment variables.

## Operations

```bash
l8tunnel-server status              # agents, tunnels, traffic, parked names
l8tunnel-agent status               # the agent's connection and tunnels
```

- **Metrics:** `metrics: {listen: 127.0.0.1:9100}` serves Prometheus metrics
  (`l8tunnel_agents_connected`, `l8tunnel_tunnel_bytes_in_total`,
  `l8tunnel_agent_rtt_seconds`, `l8tunnel_auth_failures_total`, ...).
- **Logs:** `log: {format: json, level: info}`; every public connection is
  logged with client, tunnel, duration and bytes; `access_log: true` logs
  every HTTP request.
- **State:** `/var/lib/l8tunnel` (tokens, reservations, ACME
  certificates). The admin socket is `/run/l8tunnel/admin.sock` (mode
  0600: run admin commands as root or the `l8tunnel` user).

## Install package (systemd)

```bash
./packaging/build-relay.sh amd64      # dist/l8tunnel-server-<version>-linux-amd64.tar.gz
```

On the relay machine: unpack it and run `sudo ./install.sh --cert domain.cert.pem --key private.key.pem`.
It creates the `l8tunnel` user, installs the binary, config and systemd
unit, installs the certificate (never part of the package), and starts the
service. `install-cert.sh` renews the certificate; `uninstall.sh [--purge]`
removes it. The packaged `server.yaml` is preset for layer8-tunnel.info;
`install.sh --domain example.com` uses another base domain.

## Docker

```bash
docker build --target server -t l8tunnel-server .
docker run -d -p 443:443 -p 80:80 -p 22000-22100:22000-22100 \
  -v /etc/l8tunnel:/etc/l8tunnel:ro -v l8tunnel-state:/var/lib/l8tunnel \
  --name l8tunnel l8tunnel-server
docker exec l8tunnel l8tunnel-server token create --name laptop

docker build --target agent -t l8tunnel-agent .
```

## Building

```bash
./build.sh                    # dist/<os>-<arch>/ for Linux, macOS, Windows
./build.sh linux/arm64        # one platform
cd go && go test ./tests/...  # end-to-end tests
```

The design, requirements and coding guidelines are in
[plans/PRD.md](plans/PRD.md).
