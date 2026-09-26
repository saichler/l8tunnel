# l8tunnel on Kubernetes: clustered relay, edge proxy and management app

| | |
|---|---|
| **Status** | Approved 2026-09-25; K0-K2 done, K3 next |
| **Date** | 2026-09-25 |
| **Builds on** | [PRD.md](PRD.md), [v1.1-plan.md](v1.1-plan.md), the relay and agent install packages |
| **Rules** | `../l8book/layer-8-guide-lines.md`, `../l8book/layer-8-arch.md` |

## 1. Goal

Today one relay runs as a systemd service on 192.168.1.120 (k8s-node-2). The
home router forwards 80, 443 and 22000–22999 to that one machine. This plan:

1. **Hosted service (data plane):** runs the relay as a Kubernetes workload
   with **several replicas**, behind a new **edge proxy**. The edge is the
   only thing the router forwards to. It routes every connection by domain
   (TLS SNI, HTTP Host, or destination port) and **load-balances** across
   healthy backends.
2. **Management plane:** a Layer 8 management application (Layer 8 services
   on the ORM, vnet, and an l8ui web UI for desktop and mobile). It manages
   tokens, reservations, gateway keys, agent certificates, edge domains
   (with certificate upload and port forwarding) and
   alert rules, and shows relays, edge nodes and live tunnels in real time.
3. **Keeps agents unchanged.** The agent/relay wire protocol stays the same,
   so the agent packages already deployed keep working.
4. **Keeps standalone mode.** The single-machine relay (systemd, bbolt store,
   admin CLI) stays a supported way to run l8tunnel.

### Non-goals (this plan)

- ACME certificates in cluster mode. The cluster uses the static wildcard
  certificate from a Secret (as the systemd relay does today); see §12.
- Edge high availability with a floating IP (kube-vip/keepalived). The edge
  runs on one pinned node, the one the router forwards to; see §12.
- Several agents serving one tunnel name (agent pools); see §12.
- Changes to the agent, the `l8tunnel` client or the request inspector.

## 2. Architecture

```
                 Internet
                    │  80, 443, 22000-22999, 2222 (router port forward)
                    ▼
   ┌──────────────── k8s-node-2 (192.168.1.120) ───────────────────────┐
   │  l8tunnel-edge  (hostNetwork, pinned by node label)                │
   │    SNI / Host / port ─► domains + port forwards ─► pool ─► PROXY v2│
   └───────┬──────────────────────┬──────────────────────┬─────────────┘
           │ tunnel traffic:      │ agents (connect.*):  │ other domains
           │ to the owning relay  │ least-loaded relay   │ (EdgeDomain pools)
           ▼                      ▼                      ▼
   ┌──────────────┐ ┌──────────────┐          ┌─────────────────────┐
   │ relay pod A  │ │ relay pod B  │  ...     │ e.g. l8tunnel-web,  │
   │ (sessions,   │◄┤ (forwards to │          │ other sites' web    │
   │  tunnels)    │ │  the owner)  │          │ servers             │
   └──────┬───────┘ └──────┬───────┘          └─────────────────────┘
          │  vnic          │  vnic   (edge also has a vnic)
   ═══════╪════════════════╪══════════ l8tunnel-vnet (Layer 8 overlay) ═══
          │                │       ┌──────────────────────────────────┐
          │                │       │ l8tunnel-registry (1 replica):   │
          │                │       │ sole owner of TunLive, TunAgent, │
          │                │       │ TunRelay                         │
          │                │       └──────────────────────────────────┘
   ┌──────┴────────────────┴───────────────────────────────────────────┐
   │ Management plane                                                   │
   │  l8tunnel (backend):  ORM services, Postgres   ── system services  │
   │  l8tunnel-web (UI):   l8web + l8ui, desktop and mobile   (Events,  │
   │  log-vnet, log-agent                                  Notify, Sec) │
   └────────────────────────────────────────────────────────────────────┘
```

**Boundary between hosted service and management plane.** The rules come from
`layer-8-arch.md` and the SingleOwnerDatabaseTable and SecurityRules rules:

- Only the management backend (`go/tun/main`) activates ORM services. The
  relays and the edge never touch Postgres. They use vnic RPC (GET, POST,
  PATCH, DELETE) over the vnet.
- **Pushing changes to the data plane (§16.2).** Layer 8 has no
  subscription for a process that doesn't own a service. So each owner's
  `After()` hook multicasts every change to two small **listener services**:
  `TunRlyCtl`, activated by every relay, and `EdgeCtl`, activated by every
  edge. This is the l8pollaris pattern, where `TargetCallback` multicasts to
  its collectors. At startup and every 60 s the relays and the edge also
  re-read everything with GETs, so a missed multicast heals itself.
- Every in-memory service also has exactly one owner process. The live
  tables (`TunLive`, `TunAgent`, `TunRelay`) are owned by a dedicated single-replica
  **registry** process, not by the relays (§4.2).
- All users, roles and permissions go through `ISecurityProvider` (l8secure,
  loaded as a plugin). Processes join the vnet with the project's shared
  secret and key, and the provider trusts vnet members without role checks
  (§16.3). The vnet membership is therefore the trust boundary between
  processes, and roles apply to UI users, who come in through l8web
  bearer-token auth. The project never imports l8secure.
- The relays' own access control for tunnel traffic (agent tokens,
  visitors' basic auth and OIDC, gateway keys) is **product functionality
  applied to third-party traffic**, not Layer 8 AAA. §5.7 defines its
  boundary. §15 lists it as explicit rule exceptions: agent ↔ relay auth
  (X-1) and tunnel-visitor and gateway auth (X-2), both approved by you.
- **The data plane keeps working when the management plane is down.**
  - Relays keep a local snapshot of tokens, reservations and gateway keys,
    and the edge keeps its domains and certificates (both are refreshed from change
    notifications).
  - Existing tunnels and new agent logins keep working.
  - Only management changes (for example issuing a token) wait until the
    management plane is back.

### 2.1 Components

| Component | Binary / image | Runs as | Role |
|---|---|---|---|
| Edge | `go/tun/edge` → `saichler/l8tunnel-edge` | hostNetwork, pinned to the router's target node | Listeners derived from the domain table, routing, load balancing, health checks, PROXY v2 to backends |
| Relay | `go/tun/relay` → `saichler/l8tunnel-relay` | 2+ replicas, pod network, no host ports | The existing relay in **cluster mode**: agent sessions, tunnel serving, HTTP termination, OIDC, SSH gateway |
| Registry | `go/tun/registry` → `saichler/l8tunnel-registry` | StatefulSet, 1 replica | The single owner of the in-memory live services `TunLive`, `TunAgent` and `TunRelay`: cluster-wide name, port and domain claims. No database |
| Backend | `go/tun/main` → `saichler/l8tunnel` | StatefulSet (Postgres base image) | ORM services, the issuing service, `EdgeNode`, alert evaluation |
| Web UI | `go/tun/ui` → `saichler/l8tunnel-web` | DaemonSet, hostNetwork | l8web server with l8ui, desktop `app.html` and mobile `m/app.html` |
| Vnet | `go/tun/vnet` → `saichler/l8tunnel-vnet` | DaemonSet, hostNetwork | Layer 8 overlay switch |
| Log vnet / agent | `go/tun/log-vnet`, `go/tun/log-agent` | DaemonSet (hostNetwork) / DaemonSet | l8logfusion (LogServicesRequired) |
| Standalone | `go/cmd/l8tunnel-server` (unchanged) | systemd | Single-machine relay, bbolt store, admin CLI |

The existing `go/cmd/*` binaries stay where they are, because the release
tarballs, the Dockerfile and the install packages build them. This is
exception X-4 in §15. The new Layer 8 binaries follow the l8erp layout under
`go/tun/`. `go/tun/relay/main.go` is a
second entry point to the same `tunnel/relay` package, started with
`cluster:` configuration. Relay logic is not duplicated.

## 3. Edge proxy

A new package, `go/tunnel/edge`, plus the minimal `go/tun/edge/main.go`. The
edge is managed through a **domain table** (§3.1). Each domain has uploaded
certificates and a **port forwarding table**, for example `443 → 2443`,
`14443 → 13443`, `9092 → 9093`. The edge's listeners are derived from those
tables.

### 3.1 Management model: domains and port forwards

**`EdgeDomain`** (a Prime Object, one row per site) has these fields:

- **Domain and aliases:** `domain` (for example `probler.dev`) and `aliases`
  (for example `www.probler.dev`). Aliases may be wildcards
  (`*.example.com`).
- **`kind`:**
  - `SITE`: an ordinary site the operator hosts behind the router.
  - `TUNNEL_BASE`: the built-in row for `<base>` and `*.<base>`, served by
    the relays.
- **`enabled`**, plus optional **`allow_ips` / `deny_ips`** (for example
  LAN-only for the management UI).
- **Certificates** (FileUploadPattern):
  - `cert_storage_path`, `cert_file_name`, `cert_file_size`: the full chain
    in PEM.
  - `key_storage_path`, `key_file_name`, `key_file_size`: the private key in
    PEM.
  - Both are uploaded through the Layer 8 **FileStore** service (encrypted at
    rest, SHA-256). The domain stores only the storage paths, never the bytes.
- **Certificate summary**, filled by the service callback after it validates
  an upload (§5.3): `cert_subject`, `cert_sans`, `cert_issuer`,
  `cert_not_after`, `cert_fingerprint`, and `cert_status` (`VALID`,
  `EXPIRING`, `EXPIRED`, `MISMATCH`, `MISSING`).
- **`port_forwards`**: repeated `EdgePortForward`, a child embedded in the
  domain.

**`EdgePortForward`** (one row of the domain's port forwarding table):

| Field | Meaning |
|---|---|
| `listen_port`, `listen_port_end` | The public port on the edge; `listen_port_end` is set only for a range (the relays' mode A range) |
| `protocol` | `TLS` (routed by SNI, so several domains can share a port), `HTTP` (routed by `Host`, shareable), or `TCP` (no name to route by, so the port belongs to this domain alone) |
| `mode` | `TERMINATE` (decrypt with this domain's certificate, reverse-proxy HTTP), `PASSTHROUGH` (forward the encrypted bytes untouched) or `RELAY` (only on the `TUNNEL_BASE` row) |
| `target_kind` | `TARGETS` (the explicit list below), `DNS` (every A record of `target_dns`, for headless Services and DaemonSets), `NODE_LOCAL` (the edge's own node IP, which is what the l8web proxy does with `NODE_IP`), or `RELAYS` (only on `TUNNEL_BASE`) |
| `targets` | For `TARGETS`: the load-balanced pool, as `repeated string` entries `host:port` or `host:port*weight`, for example `192.168.1.120:2443`, `192.168.1.121:2443`, `192.168.1.122:2444*2`. Each member has its own IP **and** port. A leading `!` (`!192.168.1.121:2443`) disables a member without deleting it. The callback parses and validates every entry (§16.6) |
| `target_dns`, `target_port` | For `DNS` and `NODE_LOCAL`: the name and the port, for example `2443` |
| `backend_scheme`, `skip_verify` | For TERMINATE: `HTTPS` or `HTTP` to the backend. Certificate verification is on unless `skip_verify` is set (shown as a warning) |
| `proxy_protocol` | Send PROXY v2 to the backend (PASSTHROUGH and TCP) |
| `lb`, `health_type`, `health_path`, `health_interval` | Load balancing across the pool and health checks (§3.4) |
| `enabled`, `note` | |

**Example.** Today's l8web proxy table becomes rows like these:

| Domain | Aliases | Port forwards |
|---|---|---|
| `probler.dev` | `www.probler.dev` | `443 → 192.168.1.120:2443 + 192.168.1.121:2443` (TARGETS, round robin); `9092 → 9093`, `14443 → 13443`, `9094 → 9095`, `6768 → 6767`, `5444 → 5445`, `3114 → 3113` (NODE_LOCAL). All TLS / TERMINATE / HTTPS |
| `l8erp.one` | `www.l8erp.one` | `443 → 2773` |
| `admin.layer8-tunnel.info` | | `443 → 5443` (PASSTHROUGH to `l8tunnel-web`), LAN-only `allow_ips` |
| `layer8-tunnel.info` (`TUNNEL_BASE`) | `*.layer8-tunnel.info` | `443 → relays:8443`, `80 → relays:8080`, `22000–22999 → relays:8444`, `2222 → relays:2222` (RELAY) |

The `TUNNEL_BASE` row is created by the backend at first start from the
cluster configuration. Its port forwards are read-only in the UI, because
they follow the relay configuration. Its certificate upload and IP lists can
be edited. The certificate uploaded there is the one the relays serve (§4.1).

**Validation** (done in the `EdgeDomain` callback):

- A domain or alias belongs to exactly one domain row.
- A `TCP` port belongs to one domain.
- A port can't mix protocols across domains.
- No row may overlap the relay port range or the relays' fixed ports.
- `TERMINATE` needs a valid certificate that covers the domain and its
  aliases.
- A `SITE` domain under `<base>` blocks tunnels from taking that name
  (`TunLive` checks it the way it checks reserved names).

### 3.2 Listeners derived from the table

- **The listener set** is the union of every enabled port forward.
- **Opening and closing listeners:** after every change, the edge opens new
  listeners and closes removed ones (draining open connections for up to
  60 s). It never needs a restart.
- **How a listener picks the domain:**
  - `TLS` listeners peek the ClientHello (SNI and ALPN) without terminating,
    using `tunnel/sni` from Phase K0.
  - `HTTP` listeners peek the first request's `Host` header.
  - `TCP` listeners and the relay range route by port alone. For the relay
    range, the live-tunnel table maps the port to its owner relay.
- **A port that can't be bound** (for example one already used on the node)
  doesn't stop the edge. It is reported in the edge's `EdgeNode` record, with
  the error, and shown red in the UI, and it posts an event that the alert
  rules can notify on.
- **Router ports view.** The UI shows every public port the edge listens on,
  so you know exactly which ports to forward on the router (§6).
- **Bootstrap.** Before any domain rows exist (the first start, or with the
  management plane unreachable and no cache), the edge opens the
  `TUNNEL_BASE` ports from its bootstrap ConfigMap, so tunnels work from the
  first minute.

### 3.3 Route resolution on shared TLS and HTTP ports

On a shared port, the edge checks the following in order; the first match
wins:

1. **An exact domain or alias of a `SITE` row** that has a port forward on
   this port, for example `admin.layer8-tunnel.info` or `www.probler.dev`.
2. **The control name** `connect.<base>` (on a `TUNNEL_BASE` port): goes to
   the relay pool, picking the ready relay with the fewest agent sessions.
   This balances agents across relays.
3. **A live tunnel's hostname**: `<name>.<base>`, or a custom domain from the
   live-tunnel table (§4.2). It goes to the relay that owns the tunnel. This
   is affinity, not load balancing, because only that relay holds the agent's
   session.
4. **A wildcard alias of a `SITE` row.**
5. **Anything else under `<base>`, with no SNI, or unknown:**
   - On a `TUNNEL_BASE` port, the relay pool (round robin). This keeps
     today's behavior: the relay answers with its 404 page or a TLS alert.
   - On other ports, a TLS alert or a 404 page.

If the live-tunnel table is unavailable or stale, step 3 falls back to any
ready relay. That relay forwards the connection to the owner (§4.4), so a
stale table costs one extra hop and never fails a connection.

### 3.4 Load balancing and health

- **Load balancing is per port forward.** Each port forward is its own
  pool, and every new connection (L4) or request (TERMINATE) goes to one
  healthy member of that pool. The pool is built from `target_kind`:
  - the explicit `targets` list: `ip:port` members with weights
  - the edge's own node
  - a DNS name (every A record becomes a member)
  - the relay pool (from `TunRelay` records, §4.3)

  Simulated records (§5.3) are never pool members or routes.
- **Algorithms.** Per port forward:
  - `ROUND_ROBIN` (the default; weighted when members have weights)
  - `LEAST_CONN` (fewest active connections, weighted)
  - `SOURCE_HASH` (client-IP affinity, so a client keeps hitting the same
    member; consistent hashing, so adding a member moves only a share of
    the clients)
  - `RANDOM` (power of two choices)

  For TERMINATE, the HTTP transport keeps a separate connection pool per
  member, so balancing still works with keep-alive connections.
- **Example.** `443 → 192.168.1.120:2443 ×1, 192.168.1.121:2443 ×1,
  192.168.1.122:2444 ×2` with `ROUND_ROBIN`: out of every 4 new
  connections, .122 gets 2 and the others 1 each. If .121 fails its health
  check it drops out, and .120 and .122 share the traffic 1:2 until it
  recovers.
- **Active health checks.** TCP connect, or an HTTP(S) GET on
  `health_path`, every `health_interval` (default 10 s). A member is marked down after 3 failures and
  back up after 2 successes. Relays are also marked down when their
  `TunRelay` heartbeat is older than 3 intervals, or when they report
  `DRAINING` (then they get no new agents).
- **Passive checks.** A failed dial marks the member suspect, and the edge
  retries the next member. It only retries before any client byte has been
  forwarded, so this is safe for TLS.
- **No healthy member.** A TLS forward gets a TLS alert, an HTTP forward gets
  a 503 page. The edge also posts an event and the alert rules can notify
  (§5.5).

### 3.5 Client address and trust

- **PROXY protocol v2.** The edge adds a PROXY v2 header to every
  connection it forwards to relays, and to other backends when the port
  forward sets `proxy_protocol`.
  - Relays read it on their internal listeners, so IP allow and deny lists,
    rate limits, access logs and `X-Forwarded-For` keep seeing the real
    client IP.
  - Relays accept the header only from `cluster.trusted_proxies` (CIDRs).
    A NetworkPolicy lets only edge and relay pods reach the relay's internal
    ports.
- **Per-IP connection rate limiting** moves to the edge: one edge means a
  cluster-wide limit. Relays keep their per-IP auth-failure limits locally,
  so with N relays those limits are N times looser. This is documented.
- **Per-domain `allow_ips` / `deny_ips`** are checked before any backend is
  dialed.

### 3.6 Configuration, certificates and caching

- **Loading domains.** The edge loads `EdgeDomain` rows over vnic at
  startup, applies the changes the backend pushes to its `EdgeCtl` listener,
  and re-reads everything every 60 s.
- **Loading certificates.** For every domain with a certificate, the edge
  downloads the chain and key from FileStore over vnic (§16.4). It loads them into `certs.ModeStaticSet` (§3.7), and
  reloads on every change to a domain's storage paths.
- **Cache for resilience.** The last good set is written to
  `/data/edge-cache/`: the domains as JSON, and certificates and keys as
  files with mode 0600 on the edge's own volume. The edge reads it when the
  management plane is unreachable.
- **Bootstrap ConfigMap:** the base domain, the relay pool, trusted proxies
  and the `TUNNEL_BASE` ports (§3.2).
- **Status reporting.** Every few seconds the edge writes an `EdgeNode`
  record: listener status (port, protocol, bound or error, domains), backend
  health per port forward, connections and bytes. It serves `/healthz`,
  `/readyz` and Prometheus `/metrics` (connections, bytes and dial failures
  per domain, port and member).

### 3.7 Implementation: reuse, don't port

The TERMINATE mode is assembled from l8tunnel's existing, tested packages,
not ported from `l8web/go/web/proxy` (the assessment is in §9, item 5).

- **`httpproxy`: the HTTP engine, unchanged.**
  - Its `Tunnel` interface (`ID()`, `OpenStream(ctx, clientAddr)`,
    `Access()`) is the seam. The edge's `edge/pool.go` implements it once
    per TERMINATE port forward:
    - `OpenStream` picks a healthy member with the forward's LB algorithm
      and dials it, over TLS for https backends.
    - Dial failures mark the member suspect and try the next one (§3.4).
    - `Access()` returns the domain's IP lists.
  - One `httpproxy.Proxy` serves each listener. Its `LookupFunc` maps the
    Host to the pool of that domain's forward on that port.
  - The edge then gets, with no new code:
    - HTTP/1.1 and h2 on the client side
    - streaming without buffering (`FlushInterval: -1`)
    - WebSocket upgrades through the standard reverse proxy
    - forwarded headers, with incoming `X-Forwarded-*` dropped
    - connection reuse per forward (one `http.Transport` per pool)
    - access logs and the relay's error pages
- **Two small additions to `httpproxy`:**
  1. The error handler maps "no healthy member" to 503. Other upstream
     failures stay 502.
  2. An `UpstreamTLS` option per `Tunnel`, where `verify` is the default.
     `skip-verify` comes only from the forward's `skip_verify` field.
- **One addition to `certs`: `ModeStaticSet`.**
  - It holds a set of certificates keyed by domain, including wildcards,
    built from PEM bytes (the FileStore downloads). They're parsed **once**
    and replaced atomically when a domain's certificate changes.
  - It selects a certificate by SNI. An unknown SNI gets a handshake
    failure; it never falls back to another domain's certificate.
  - The relay's existing `ModeStatic` and ACME modes are untouched.
- **Also reused:** `tunnel/sni` (K0) for peeking at the connection and
  `tunnel/pipe` for L4 copying.
- **New code in `tunnel/edge`:**
  - dynamic listeners and route resolution
  - pools and health checks
  - the PROXY v2 writer
  - the FileStore certificate loader and the cache
  - `EdgeNode` reporting

## 4. Relay cluster mode

The relay keeps all of its serving logic. Cluster mode changes where the
shared state lives and how connections arrive.

### 4.1 What moves out of bbolt

| State | Standalone (today) | Cluster mode |
|---|---|---|
| Tokens, policies, cert serials | bbolt | `TunToken` (ORM). Each relay keeps a read cache fed by change notifications, plus a snapshot on `/data` |
| Permanent reservations | bbolt | `TunReservation` (ORM) |
| Gateway keys and grants | bbolt | `TunGatewayKey` (ORM) |
| Issued agent certificates | serials on the token | `TunAgentCert` (ORM). A certificate is accepted only while its serial is listed and not revoked |
| Agent CA certificate and key | bbolt | A Kubernetes Secret mounted in every relay (the backend signs with it too) |
| TLS certificate for `<base>` and `*.<base>` | files | Uploaded on the `TUNNEL_BASE` domain row (§3.1) and stored in FileStore. Relays download it over vnic, reload it on change, and keep a 0600 copy on `/data`. An optional `l8tunnel-tls` Secret is used only for the very first start, before any upload |
| OIDC signing key, OIDC client secrets | bbolt / files | Secrets shared by all relays, so cookies and codes validate on any relay |
| Active names, ports, domains, grace holds | in memory, per relay | `TunLive`: a cluster-wide in-memory service (§4.2) |
| Relay status | the admin socket | A `TunRelay` record, heartbeat every 5 s |

**Phase K0 refactor.** The relay gets two interfaces:

- `relay.Accounts`: token lookup, reservations, gateway keys, cert validity,
  and change events.
- `relay.Registry`: claim, park, release and look up names, ports and domains.

Today's bbolt store and in-memory `registry` become the standalone
implementations. The new `tunnel/cluster` package implements both over vnic.
Policy checks (`auth.Policy`, name rules, domain patterns) stay in `auth`, so
the standalone admin API and the management callbacks both call the same
validation code.

### 4.2 The cluster-wide live table (`TunLive`)

- **Registration.** When an agent registers, its relay POSTs one
  `TunLiveTunnel` per tunnel. The service callback's `Before()` enforces what
  `registry.claim` enforces today, but cluster-wide:
  - unique names, hostnames, custom domains and mode A ports
  - `max_tunnels` per token
  - honoring permanent reservations
  - allocating a free port from `tcp_port_range` when `public_port` is 0

  It rejects a conflict with the same error codes, and the relay passes them
  back to the agent unchanged.
- **Takeover.** A registration from the same agent ID and token replaces the
  record, even from another relay. The old relay sees the change
  notification and closes its stale session. This is today's takeover
  behavior across relays.
- **Grace period.** When a session drops, its records switch to `GRACE` with
  `grace_until`, so the name stays held for the token cluster-wide. The next
  registration from that token reclaims it on any relay.
- **Hosting (one owner, SingleOwnerDatabaseTable).** `TunLive` and
  `TunRelay` are activated in **exactly one process**: the registry
  (`go/tun/registry`, a StatefulSet with one replica).
  - Relays, the edge, the backend and the UI never activate these services.
    They use vnic RPC. The registry's `After()` pushes the changes relays
    and edges act on (takeovers, disconnects, drains) to `TunRlyCtl` and
    `EdgeCtl` (§16.2).
  - The registry has no database and doesn't depend on the management
    backend or Postgres. New agent registrations keep working while the
    management plane is down.
- **Registry restart.** The state is rebuilt, not persisted.
  - On startup the registry multicasts a re-announce request to `TunRlyCtl`,
    and every relay re-POSTs its agents and its active and grace records. The registry's `/readyz` stays
    false until all relays known from their heartbeats have re-announced, or
    for up to 15 s.
  - Existing tunnels keep carrying traffic throughout; relays keep their own
    local copy of their tunnels.
  - Only new claims wait. The relay retries a claim for up to 10 s, then
    returns the existing `UNAVAILABLE` error, and the agent's normal backoff
    retries it.
  - The edge keeps its last live-table snapshot and falls back to
    relay-to-relay forwarding (§4.4).
- **Lost relay.** When a relay's heartbeat is older than 3 intervals, the
  registry moves its records to `GRACE`. Its agents reconnect through the
  edge to other relays and reclaim their names.

### 4.2a Agent records (`TunAgent`)

One record per agent, keyed by the agent ID, beside the per-tunnel
`TunLiveTunnel` records. It's owned by the registry like them.

- **Created at login.** When an agent's session is authenticated, its relay
  POSTs (or replaces, on takeover) the `TunAgent` record with:
  - from the `Hello` message the agent already sends: agent ID, version, OS
    and architecture
  - how it authenticated: the token ID and name, or the agent-certificate
    serial
  - session details: session ID, public IP (from PROXY v2), relay ID,
    transport (TLS, WebSocket, or WebSocket through an HTTP proxy), and
    connected-since
- **Heartbeats.** The relay PATCHes the agent's heartbeat data (the last
  heartbeat time and the round-trip time it already measures with
  Ping/Pong), tunnel count, active streams and bytes, together with its own
  5 s `TunRelay` heartbeat. That's one batched update per relay, not one per
  agent.
- **State:**
  - `ONLINE`
  - `GRACE`: the session dropped and its names are held, until `grace_until`
  - `OFFLINE`: kept with `last_seen` and the last disconnect reason
    (heartbeat timeout, revoked token, relay drained or lost, takeover, or
    closed by the agent) for 24 hours, then removed. Agent history beyond
    that comes from the session events (§5.4).
- **Disconnect.** `DELETE` from the UI disconnects the agent: the owning
  relay closes the whole session, including all its tunnels. The agent
  reconnects by itself unless its token was revoked. A disconnect button,
  not revocation, is what operators need for a stuck agent.
- **Rebuilt on restart.** The registry's re-announce (§4.2) covers
  `TunAgent` too: relays re-POST their agents before their tunnels.
- **No new wire protocol.** Everything comes from data the relay already
  has.

### 4.3 Relay listeners in cluster mode (pod network, unprivileged)

| Port | Traffic | Notes |
|---|---|---|
| 8443 | PROXY v2, then the original TLS stream (everything the edge sends from 443) | Goes through the existing SNI/ALPN router unchanged |
| 8080 | PROXY v2, then HTTP (from port 80) | The existing redirect handler |
| 8444 | PROXY v2 with l8tunnel TLVs (tunnel name, HMAC), then a raw stream into the named tunnel | Mode A traffic from the edge (it maps port → tunnel), plus relay-to-relay forwarding (§4.4). This replaces a listener per mode A port |
| 2222 | SSH gateway (optional) | The edge round-robins to any relay |
| 9100 | `/healthz`, `/readyz`, `/metrics` | New endpoints, also added to standalone mode |

The relay advertises `POD_IP` and these ports in its `TunRelay` record.

### 4.4 Relay-to-relay forwarding

A relay that receives a connection for a tunnel it doesn't own forwards it to
the owner over the owner's internal ports, keeping the original client
address in the PROXY header. This happens when:

- the edge's table was stale
- the SSH gateway reaches a tunnel on another relay
- an OIDC auth host redirect lands elsewhere

A TLV marks the connection as forwarded. A receiving relay that doesn't own
the tunnel either rejects it (no second hop, so no loops) or serves the 404
page. The TLV carries an HMAC made with a cluster secret, so other pods can't
spoof tunnel streams on 8444.

### 4.5 Draining and scaling

- **Draining.** Setting a relay to `DRAINING` (a UI action, or the `preStop`
  hook during rollouts and scale-down) makes the edge stop sending it new
  agents. The relay then closes its agent sessions at a paced rate. The
  agents reconnect (they already back off with jitter), land on another
  relay, and reclaim their names through the grace period.
  - Public connections already in progress finish, up to
    `terminationGracePeriodSeconds` (60 s).
- **Scaling.** Scaling up only needs more replicas. New agents go to the
  least-loaded relay, and existing agents move only when a relay drains.
  There's no autoscaler; replicas are set by hand (default 2).

### 4.6 Other features in cluster mode

- **OIDC:** the auth host (`auth.<base>`) is load-balanced to any relay.
  Login codes are redeemed at the tunnel host, and that always lands on the
  tunnel's owner relay. So the owner's in-memory single-use check still
  holds; the signing key is shared.
- **Custom domains:** these work in PASSTHROUGH tunnels. For HTTP-terminated
  custom domains the relay needs certificates issued on demand, which needs
  ACME, so it is refused at registration in cluster mode until ACME is added
  (§12).
- **Admin socket:** disabled in cluster mode (fail-fast if configured).
  Management goes through the UI and REST instead. The standalone CLI stays.
- **Metrics:** per relay, as today, plus the `TunRelay` counters for the
  dashboard.

## 5. Management plane (Layer 8)

The canonical project is **l8erp** (CanonicalProjectSelection): this is CRUD
over configuration entities, not a collection pipeline. The live records are
pushed by relays and edges, not polled, so the probler pattern doesn't apply.

### 5.1 Layout (l8erp structure)

```
go/tun/
├── common/               # PREFIX "/tun/", service areas, defaults
├── access/
│   ├── tokens/           TunTokenService.go, TunTokenServiceCallback.go
│   ├── reservations/     TunResvService.go, ...Callback.go
│   ├── gwkeys/           TunGwKeyService.go, ...Callback.go
│   ├── agentcerts/       TunAgCertService.go, ...Callback.go
│   └── issue/            TunIssueService.go (non-ORM: returns secrets once)
├── edge/domains/         EdgeDomainService.go, ...Callback.go (certificate validation via FileStore)
├── edge/nodes/           EdgeNodeService.go (in-memory, TTL)
├── live/tunnels/         TunLiveService.go, ...Callback.go (in-memory, activated only by the registry)
├── live/agents/          TunAgentService.go, ...Callback.go (in-memory, activated only by the registry)
├── live/relays/          TunRelayService.go (in-memory, activated only by the registry)
├── alerts/               TunAlertService.go, ...Callback.go, evaluator.go
├── main/  registry/  vnet/  relay/  edge/  log-vnet/  log-agent/     # main.go each (minimal)
├── ui/main.go            # l8web server + type registration
└── ui/web/               # app.html, login.html, login.json, l8ui/ (submodule), sections/, m/
go/types/tun/             # generated from proto/tun.proto
go/tests/                 # Go end-to-end tests (existing + cluster) and mocks/
proto/tun.proto           # management model (proto/l8tunnel.proto, the wire protocol, is unchanged)
```

### 5.2 Services and Prime Objects

ServiceName ≤ 10 characters; one ServiceArea per module.

| Module (area) | ServiceName | Prime Object (protobuf type) | PK | Storage | Owner process |
|---|---|---|---|---|---|
| access (40) | `TunToken` | `TunToken` | `tokenId` | ORM | backend |
| access (40) | `TunResv` | `TunReservation` | `reservationId` | ORM | backend |
| access (40) | `TunGwKey` | `TunGatewayKey` | `keyId` | ORM | backend |
| access (40) | `TunAgCert` | `TunAgentCert` | `certId` (the serial) | ORM | backend |
| access (40) | `TunIssue` | `TunIssueRequest` (request/response only, not persisted) | — | none | backend |
| edge (41) | `EdgeDomain` | `EdgeDomain` | `domainId` | ORM | backend |
| system (0) | `FileStore` (l8services, not project code) | uploaded certificate and key files | `storagePath` | encrypted files on `/data/l8files` | web UI process (§16.4) |
| live (42) | `TunRlyCtl` | listener only: receives pushed changes (tokens, reservations, gateway keys, certificates, takeovers, disconnects, drains, re-announce) | — | none | every relay (§16.2) |
| edge (41) | `EdgeCtl` | listener only: receives pushed `EdgeDomain`, `TunLive` and `TunRelay` changes | — | none | every edge (§16.2) |
| edge (41) | `EdgeNode` | `EdgeNode` | `edgeId` | in-memory, TTL | backend |
| live (42) | `TunLive` | `TunLiveTunnel` | `tunnelId` | in-memory | registry (§4.2) |
| live (42) | `TunAgent` | `TunAgent` | `agentId` | in-memory | registry (§4.2a) |
| live (42) | `TunRelay` | `TunRelay` | `relayId` | in-memory | registry |
| alerts (43) | `TunAlert` | `TunAlertRule` | `ruleId` | ORM | backend |

**Children** (embedded as `repeated` fields, with no service, UI nav or
generator of their own):

- `TunTokenPolicy` and `TunPortRange` in `TunToken`
- `TunGatewayGrant` in `TunGatewayKey`
- `EdgePortForward` in `EdgeDomain` (the port forwarding table), with its
  load-balancing pool as a `repeated string targets` field (§16.6)
- `EdgeBackendStatus` in `EdgeNode`

**References between Prime Objects** are ID strings only, for example
`TunLiveTunnel.tokenId`, `TunLiveTunnel.relayId`, `TunLiveTunnel.agentId`,
`TunAgent.tokenId`, `TunAgent.relayId`, `TunAgentCert.tokenId` and
`TunReservation.tokenId`.

**`TunAlertRule.targets`** embeds the shared `l8notify.NotifyTarget` type.

**Protobuf rules:**

- Every enum starts with `*_UNSPECIFIED = 0`. The enums: `TunTunnelType`,
  `EdgeDomainKind`, `EdgeCertStatus`, `EdgeProtocol`, `EdgeForwardMode`,
  `EdgeTargetKind`, `EdgeBackendScheme`, `EdgeLbAlgorithm`, `EdgeHealthType`, `TunRelayState`,
  `TunAgentState`, `TunAgentTransport`, `TunDisconnectReason`,
  `TunLiveState`, `TunAlertCondition` and `TunIssueKind`.
- Every `XxxList` type has `repeated Xxx list = 1; l8api.L8MetaData metadata = 2;`.
- Bindings are generated only through `proto/make-bindings.sh` (`docker run -i`).

### 5.3 Service callbacks (key behavior)

**`TunToken`**

- `Before(POST)` generates `tokenId` (`common.GenerateID`) and validates the
  name and policy with the shared `auth` validators.
- `secretHash` is written only by `TunIssue`, or by import. The UI never
  shows it, and a PUT with an empty hash keeps the stored one. There's no
  field-level deny rule for it (removed in K7, §16.15).
- `DELETE` revokes the token. Relays see the notification and drop that
  token's sessions for good, and its certificates stop validating (today's
  revocation behavior, cluster-wide).

**`TunIssue`** (POST only): three kinds.

- `TOKEN`: creates the token, stores only the bcrypt hash through `TunToken`
  over vnic, and returns `l8t_<id>_<secret>` once.
- `AGENT_CERT`: signs with the agent CA from the Secret, records a
  `TunAgentCert`, and returns the certificate and key PEM once.
- `IMPORT`: accepts a standalone export (§7.5) and keeps token IDs and hashes,
  so existing agent tokens stay valid.

Plaintext secrets never reach the ORM or the event log.

**Other callbacks**

- **`TunResv`, `TunGwKey`:** validation uses the same rules as the
  standalone admin API.
- **`EdgeDomain`:**
  - `Before(POST)` generates `domainId`. Every POST, PUT or PATCH runs the
    §3.1 validation: domain and alias uniqueness, port and protocol
    conflicts, no overlap with the relay ports, and health-check bounds.
  - **Certificate check.** When `cert_storage_path` or `key_storage_path`
    changes, the callback fetches both files **from FileStore over vnic**
    (no file I/O in the callback, per FileUploadPattern). It then checks:
    - the chain parses
    - the key matches the leaf
    - the leaf covers the domain and every alias (wildcards included)
    - it's within its validity dates

    It fills the certificate summary fields. A mismatch rejects the save,
    with a clear message such as "certificate doesn't cover
    www.probler.dev".
  - **Protected fields.** Only the callback writes the summary fields; values
    a client sends are ignored.
  - **`TUNNEL_BASE` row.** The backend creates it at first start. Its
    `port_forwards` and `kind` can't be changed through the API, and it
    can't be deleted.
  - **Version.** Every accepted change bumps a `configVersion` that edges
    report back, so the UI shows whether each edge has applied it.
  - **Events.** Certificate uploads and replacements post events. The
    certificate summary feeds `CERT_EXPIRING` (§5.5).
- **`TunLive`, `TunAgent`, `TunRelay`, `EdgeNode` and simulated records:**
  - Each type has a `simulated` boolean. It is accepted only when the
    owning process runs with `L8TUNNEL_ALLOW_SIMULATED=true`, which only
    `run-local.sh` and the KIND manifests set. Everywhere else a simulated
    record is refused (§16.3).
  - Simulated records are exempt from heartbeat expiry, never take part in
    claims against real tunnels (they use names under the reserved `demo-`
    prefix), and are ignored by the edge's route resolution and the relays.
    The UI marks them with a "simulated" badge.
  - This is what lets the mock generators (§7.4) fill the live services
    without a fake relay being routed to.
- **`TunLive`:**
  - `Before()` implements §4.2.
  - `DELETE` from the UI means "disconnect": the owning relay closes that
    tunnel.
  - Relays PATCH their counters.
- **`TunAgent`:** only relays POST and PATCH (§4.2a). `DELETE` from the UI
  disconnects the agent, and posts an event naming the user who did it. The
  registry's cleanup moves records to `OFFLINE` and removes them after
  24 hours.
- **`TunRelay`:** relays PATCH their heartbeat, state and counters. A UI
  PATCH of `state` to `DRAINING` starts a drain.

### 5.4 Events (l8events, EventsServiceRequired)

Events go through `vnic.Resources().Events().PostXxxEvent(...)`, fire and
forget. The exact category methods are chosen in K1 from the 16 converters in
`l8utils`. Events:

- token issued or revoked, certificate issued or revoked, reservation and
  gateway-key changes (backend)
- agent session up/down and tunnel registered/unregistered (relays; these can
  be turned off with `cluster.events.sessions: false`)
- relay joined, draining or lost (relays and the registry)
- edge backend down or up, listener bound or failed, and domain configuration applied (edge)
- domain certificate uploaded or replaced (backend)
- certificate expiring (backend)

The project never activates `Events` itself (l8common does), and the UI
`main.go` registers `EventRecord`.

### 5.5 Notifications (l8notify, NotifyServiceRequired)

- `TunAlertRule` conditions:
  - `RELAY_LOST`
  - `NO_READY_RELAY`
  - `EDGE_POOL_DOWN`
  - `CERT_EXPIRING` (threshold in days) for every domain's certificate
    (`EdgeDomain.cert_not_after`). The tunnel wildcard currently expires on
    Dec 24, 2026.
  - `EDGE_LISTENER_FAILED` (a port forward's listener couldn't bind)
  - `TOKEN_OFFLINE` (all of a token's `TunAgent` records `OFFLINE` for
    longer than N minutes)
  - `AGENT_OFFLINE` (a specific agent ID offline for longer than N minutes,
    for important machines)
- The backend's `alerts/evaluator.go` subscribes to `TunRelay`, `EdgeNode`,
  `EdgeDomain`, `TunAgent` and `TunLive`. When a condition matches it sends through
  `vnic.Resources().Notify().Send(...)` to each target, with a per-rule
  cooldown.
- Deliveries appear in the shared delivery log. There's no project SMTP or
  webhook code. SMTP and webhook endpoints are `IntegrationConfig` entries
  (UI), and their secrets go in the security config `credentials` map.
- Bodies never include secrets (the NotifyRecord gotcha).
- The UI `main.go` registers `NotifyRecord` and `IntegrationConfig`.

### 5.6 Security (SecurityRules, SecurityConfigStructure)

- **Security config** `l8secure/go/secure/plugin/l8tunnel/l8tunnel.json` in
  the l8secure repository. Roles:
  - `admin`: everything
  - `operator`: live views, drain, disconnect, reservations, and edge
    domains and port forwards (not certificate upload); cannot issue tokens or
    certificates
  - `viewer`: read-only
  - The relays, edge, registry and backend need no roles. They're vnet
    members, which l8secure trusts (§16.3). The vnet's ports aren't
    forwarded on the router, and joining needs the shared secret.
  - Mock data is uploaded over REST as a normal `admin` user.
- **No deny rule on `secretHash`** (removed in K7, §16.15). Relays read it
  over the vnet.
- **FileStore:** the rules are action-level on the message types. Upload
  (`L8FileUploadRequest`) and download (`L8FileDownloadRequest`) are
  allowed for `admin` only. Operators and viewers see a domain's certificate
  summary but can never fetch a private key, and the UI never offers a key
  download. The edge and relays download over the vnet.
- **Provisioning** of users and roles goes only through the config JSON or
  the Security API (area 73), including from the mock data. There's no
  project-owned users service, and the project never imports l8secure.
- **Management UI exposure:** served through the edge as
  `admin.<base>` (PASSTHROUGH to `l8tunnel-web`, which serves the wildcard
  certificate). Its `EdgeDomain` row has a LAN-only `allow_ips` by
  default, and
  l8secure TFA is enabled in `login.json`.

### 5.7 Data-plane access control and `ISecurityProvider`

SecurityRules requires every AAA concern of a Layer 8 project to go through
`ISecurityProvider`. This plan splits l8tunnel's security into two planes and
puts that line in writing.

**Management plane: fully under `ISecurityProvider`, no exceptions.**

- Every REST, vnic and UI operation on every service in §5.2 is
  authenticated and authorized by l8secure, including:
  - issuing and revoking tokens and certificates
  - drain and disconnect
  - edge domain, port forward and certificate changes
- Only the §5.6 roles apply. Users are provisioned only through the security
  config JSON or the Security API (area 73).
- Every management action is recorded as an event.
- The relays, the edge and the registry are vnet members, authenticated by
  the project's shared secret and key (§16.3). They expose no management
  API of their own.

**Data plane: the product's own access control for third-party traffic
(exceptions X-1 and X-2, §15).**

- **What it covers.** Agents (X-1) are authenticated to relays with tokens and
  mTLS certificates. Tunnel visitors (X-2) are checked by the tunnel owner's
  policy: IP lists, basic auth, OIDC login cookies and SSH access tokens.
  SSH gateway users (X-2) are checked with gateway keys.
- **Why it isn't an `ISecurityProvider` concern:**
  - These principals aren't users of the Layer 8 application. They are
    agents and anonymous internet clients reaching the operator's customers'
    services.
  - Their credentials are created by tunnel owners (basic-auth users,
    access-token hashes and OIDC allow-lists arrive in the agent's
    `Register` message) or are wire-protocol secrets.
  - The checks run for every connection on the hot path, and must keep
    working while the management plane is down (§2).
  - Routing them through `ISecurityProvider` would mean provisioning every
    visitor as an l8secure user, which the provider's user model and
    SecurityRules' provisioning rule don't allow.
- **Boundaries that keep it from becoming "custom auth middleware" for the
  Layer 8 app:**
  1. Data-plane credentials never grant access to any Layer 8 service, REST
     endpoint or UI, and management credentials are never accepted by the
     data plane.
  2. The data-plane code (`go/tunnel/*`) never handles Layer 8 users or
     sessions. The `go/tun/*` management code never contains authentication
     logic of its own; it only calls `ISecurityProvider` through l8web and
     vnic.
  3. The objects that *define* data-plane access (`TunToken`,
     `TunAgentCert`, `TunGatewayKey`, `TunReservation`) are managed only
     through Layer 8 services governed by `ISecurityProvider`. Who may
     create, change or revoke agent access is therefore a Layer 8
     authorization decision.
  4. Data-plane accounting goes through Layer 8: session and tunnel events
     (§5.4), `TunLive` records and relay metrics.
  5. The OIDC login for tunnel visitors keeps its own signed cookies, per
     tunnel host, and never shares cookies or keys with the l8web
     management session.
- **Checks in K7.**
  - `grep` shows no import of `go/tunnel/auth` from `go/tun/*` except the
    shared validators (policy and name rules) and `TunIssue`'s token
    hashing.
  - A test confirms an agent token is refused by the management REST API,
    and a management bearer token is refused as an agent credential.

## 6. Management UI (l8ui, desktop and mobile)

`go/tun/ui/web/app.html` and `m/app.html` follow the l8erp shell
(AppHtmlBodyFromL8erp), with scripts in the canonical loading order and a
startup dependency check (FailFastNoSilentFallback). `login.json` sets
`appTitle: "l8tunnel"`, `apiPrefix: "/tun"` and `tfaEnabled: true`. Each
section is config, enums, columns, forms and init, and init calls
`Layer8DModuleFactory.create()`. Mobile uses the `Layer8M*` equivalents with
`LAYER8M_NAV_CONFIG`.

| Section | Services | Desktop | Mobile | Notes |
|---|---|---|---|---|
| Dashboard | TunRelay, TunAgent, TunLive, EdgeNode | Layer8DWidget KPIs: ready relays, agents online (from `TunAgent`), agents offline in the last 24 h, tunnels by type, unhealthy backends, days to certificate expiry | Mobile widgets | KPI counts query `page 0` (L8QL gotcha) |
| Tunnels ▸ Agents | `TunAgent` | **Agent status screen**: a Layer8DTable in `realtime` mode with state badge (online, grace, offline), agent ID, token or certificate, version, OS and architecture, public IP, relay, transport, connected-since or last-seen, heartbeat RTT, and tunnel count. Filters by state, token and relay. The read-only detail adds the disconnect reason, bytes and streams, and the agent's **tunnels** as a read-only table (`TunLiveTunnel where agentId=…`). Actions: **Disconnect agent** (with confirmation), and **Open token** | Layer8MTable cards with the same fields, detail and actions | Immutable, so read-only apart from the actions (ImmutabilityUiAlignment). A version column highlights agents older than the relay's version |
| Tunnels ▸ Live | `TunLiveTunnel` | Layer8DTable `realtime`, read-only view form, the agent ID as a link to its agent row, **Disconnect** action | Layer8MTable, read-only card | Immutable, so read-only UI (ImmutabilityUiAlignment) |
| Tunnels ▸ Relays | `TunRelay` | Table (realtime), **Drain / Resume** actions | Same | Read-only apart from the state action |
| Tunnels ▸ Edge nodes | `EdgeNode` | Table; listener status and backend health as read-only inline tables | Same | |
| Access ▸ Tokens | `TunToken` | CRUD; the policy as form sections with an inline table for port ranges; **Issue token** runs a custom handler that POSTs to `TunIssue` and shows the token once, with copy | Same (mobile form and confirm) | `secretHash` never shown |
| Access ▸ Reservations | `TunReservation` | CRUD, token reference picker | Same | |
| Access ▸ Gateway keys | `TunGatewayKey` | CRUD, grants as an inline table | Same | |
| Access ▸ Agent certificates | `TunAgentCert` | List + **Issue certificate** (shown once, downloaded as PEM) + revoke (PATCH) | Same | |
| Edge ▸ Domains | `EdgeDomain` | **Domain table**: domain, aliases, kind, certificate status (a colored badge with days to expiry), number of port forwards, and applied-on-all-edges. **Detail form:**<br>• **General:** domain, aliases, enabled, IP lists.<br>• **Certificate:** two `f.file` fields, the certificate chain and the private key (`Layer8FileUpload`, POST to `/0/FileStore`), plus the read-only summary (subject, SANs, issuer, expiry, fingerprint, status). The certificate can be downloaded; the private key can't.<br>• **Port forwarding:** `f.inlineTable('portForwards', …)` with listen port (and range end), protocol, mode, target kind, LB algorithm, number of healthy/total members, backend scheme, skip-verify (with a warning), PROXY v2, health type and path, and enabled. Each port-forward row's **targets** are edited as tags (`f.tags`), one `host:port` or `host:port*weight` tag per member, with `!` to disable one; the DNS name and port are plain fields for the other target kinds.<br>The `TUNNEL_BASE` row's port forwards are read-only | Same, as mobile cards: domain list, then detail with the certificate upload and port-forward cards (`Layer8MForms` file fields, `Layer8MEditTable`) | Validation errors from the callback (for example "certificate doesn't cover www.probler.dev" or "port 9092 is TCP on another domain") are shown on the form |
| Edge ▸ Router ports | `EdgeNode` (listener status) | A read-only table of every public port the edge listens on: port or range, protocol, domains, and bound or error. This is the list of ports to forward on the home router | Same | Derived from the edge's report, so it shows what's really bound, not only what's configured |
| Alerts ▸ Rules | `TunAlertRule` | CRUD; targets use `l8notify-target-editor.js` | Same | |
| System | built-in | l8ui SYS: health, security (users and roles), modules, logs (L8Logs), data import; Events (`l8ui/events/`); Notify integrations and delivery log (`l8ui/notify/`) | Mobile SYS equivalents | |

- **Registration:** reference registry entries for every Prime Object (the
  token, domain and relay pickers), and types registered in `go/tun/ui/main.go`.
- **Theming:** only `--layer8d-*` tokens, with `var(--layer8d-on-primary, white)`
  on primary backgrounds, and no project CSS using the l8ui alias names.
- **No project code in l8ui** (L8UINoProjectSpecificCode). Custom behavior
  (the show-once popups) lives in `go/tun/ui/web/sections/`.

## 7. Deployment

### 7.1 Images (DeploymentArtifacts)

Each image is a multi-stage Docker build: `saichler/builder:latest`, then the
project's own base image. `build.sh` in each binary's directory runs
`docker build --no-cache --platform=linux/amd64 … && docker push`.

| Image | Directory | Base | Local | Bare-metal / KIND | GKE |
|---|---|---|---|---|---|
| `saichler/l8tunnel` | `go/tun/main` | `l8tunnel-postgres` | StatefulSet | StatefulSet + volumeClaimTemplates | StatefulSet, shared PVC |
| `saichler/l8tunnel-web` | `go/tun/ui` | `l8tunnel-security` | DaemonSet (hostNetwork, nodeSelector `l8tunnel.io/edge: "true"`, so exactly one instance; §16.4) | StatefulSet (1) + anti-affinity + nodeSelector | DaemonSet with the same nodeSelector |
| `saichler/l8tunnel-vnet` | `go/tun/vnet` | `l8tunnel-security` | DaemonSet (hostNetwork) | StatefulSet + anti-affinity | DaemonSet |
| `saichler/l8tunnel-registry` | `go/tun/registry` | `l8tunnel-security` | StatefulSet (1 replica) | StatefulSet (1) + volumeClaimTemplates | StatefulSet (1), shared PVC |
| `saichler/l8tunnel-relay` | `go/tun/relay` | `l8tunnel-security` | Deployment (2 replicas) | StatefulSet (2) + volumeClaimTemplates | Deployment |
| `saichler/l8tunnel-edge` | `go/tun/edge` | `l8tunnel-security` | DaemonSet (hostNetwork, nodeSelector `l8tunnel.io/edge: "true"`) | StatefulSet (1) + anti-affinity + nodeSelector | DaemonSet |
| `saichler/l8tunnel-log-vnet` | `go/tun/log-vnet` | `l8tunnel-security` | DaemonSet (hostNetwork) | StatefulSet + anti-affinity | DaemonSet |
| `saichler/l8tunnel-log-agent` | `go/tun/log-agent` | `l8tunnel-security` | DaemonSet | StatefulSet + anti-affinity | DaemonSet |

- **Base images.** `saichler/l8tunnel-security` and
  `saichler/l8tunnel-postgres` are built with `../security/build.sh l8tunnel`
  and `../postgres/build.sh l8tunnel` (as probler does), never the erp base
  images. The final stages don't `apk upgrade` (plugin ABI gotcha).
- **Edge port 443.** The edge binds 443 as non-root, using `setcap
  cap_net_bind_service` in the image and
  `capabilities.add: [NET_BIND_SERVICE]`.
- **Shared scripts.** `go/build-all-images.sh`, `k8s/deploy.sh` and
  `k8s/undeploy.sh` list every image in phase order: vnet and logs, then the
  backend and the registry, then relays, the edge and the web UI.
- **Existing artifacts.** The root `Dockerfile` (standalone distroless
  images) and `packaging/` stay for standalone installs. They are not part
  of any Kubernetes deployment, never join a vnet and load no security
  plugin, so they don't use the `-security`/`-postgres` base images
  (exception X-5, §15). Every image this plan introduces uses them.

### 7.2 Kubernetes (K8sRules)

- **Files:** `k8s/l8tunnel-{local,baremetal,gke,kind}.yaml`, plus
  `k8s/kind-start.sh` and `k8s/kind-stop.sh` (`kind-start.sh` uses a kind
  config with `extraPortMappings` for 443, 80 and a small mode A port range on
  the edge node, so the E2E tests reach it through `localhost`).
- **Every mode includes:**
  - namespace `l8tunnel` with `labels: {name: l8tunnel}`
  - `app:` labels
  - `NODE_IP` from `status.hostIP` (and `POD_IP`/`POD_NAME` for relays)
  - a volume named `hdata` at `/data`
  - the same images, env, ports, Services, ConfigMaps (relay and edge
    bootstrap config) and Secrets
    - Secrets are referenced but never committed: `l8tunnel-agent-ca`,
      `l8tunnel-cluster`, `l8tunnel-oidc`, and the optional first-start
      `l8tunnel-tls`. Site and tunnel certificates are uploaded in the UI
      (§3.1), not kept as Secrets.
    - `k8s/secrets.sh` creates them from files.
  - a NetworkPolicy for the relay's internal ports
  - a headless Service for the relays
- **Storage by mode:** local uses hostPath `DirectoryOrCreate`; bare-metal
  uses `rancher.io/local-path` (Delete); GKE uses `kubernetes.io/gce-pd` with
  the shared `l8tunnel-data` PVC (Retain); KIND uses `standard`.
- **Your cluster:** `k8s/label-edge.sh <node>` labels k8s-node-2, because the
  router forwards to its static IP 192.168.1.120.

### 7.3 Local development (RunLocalScript)

**Waived (X-6, 2026-09-26):** there is no `run-local.sh` and no demo agent;
development and tests run in KIND. The original plan follows for the
record.

`go/run-local.sh`, adapted from `l8erp/go/run-local.sh`:

1. Starts the Postgres container.
2. Builds every binary into `demo/` and copies the web assets.
3. Generates `kill_demo.sh`.
4. Starts vnet, logs, backend, registry, two relays, the edge (unprivileged
   ports 8443/8080 with a local test domain) and the UI.
5. Uploads the mock data.
6. Starts one real demo agent, so the real data path is exercised next to
   the simulated records.
7. Waits for the user, then cleans up.

The PRD gets a "Local Development Setup" section.

### 7.4 Mock data (MockDataRules): a generator for every service

Everything lives in `go/tests/mocks/`:

- `data.go`: name arrays
- `store.go`: ID slices, prefixed `Tun…IDs`
- one `gen_<module>_<group>.go` per group, each under 500 lines
- `tun_phases.go`
- `main.go`

Endpoints use `/tun/<area>/<ServiceName>` with the exact `ServiceName`
constants. Users and roles are provisioned only through the Security API
(area 73).

| Phase | Service(s) | Generator | Depends on |
|---|---|---|---|
| 1 | `TunIssue` → `TunToken` | `gen_access_tokens.go`: 20 tokens through `TunIssue` (the only way to create one), with varied policies. Records `TunTokenIDs` | — |
| 2 | `TunResv`, `TunGwKey` | `gen_access_resv.go`: reservations on token IDs. `gen_access_gwkeys.go`: generated ed25519 public keys with grants | `TunTokenIDs` |
| 3 | `TunIssue` → `TunAgCert` | `gen_access_certs.go`: certificates for a subset of tokens | `TunTokenIDs` |
| 4 | `FileStore` → `EdgeDomain` | `gen_edge_domains.go`: 8 `SITE` domains with aliases. For each it generates a self-signed certificate and key for the domain (`demo-*.invalid`), uploads both through `/0/FileStore`, and stores the returned paths. It also creates port forwards in every protocol, mode, target kind and LB algorithm (target pools of 1–4 weighted members, some disabled), including one expired certificate and one expiring soon for the status badges | — |
| 5 | `TunAlert` | `gen_alerts.go`: one rule per condition, with email and webhook targets | `TunTokenIDs` |
| 6 | `TunRelay`, `EdgeNode` | `gen_live_relays.go`: 3 simulated relays and 1 simulated edge node (`simulated: true`, §5.3) | — |
| 7 | `TunAgent` | `gen_live_agents.go`: 25 simulated agents across the simulated relays and tokens, in every state (ONLINE, GRACE, OFFLINE with each disconnect reason), transport, OS and architecture, and a few older versions. Records `TunAgentIDs` | phases 1 and 6 |
| 8 | `TunLive` | `gen_live_tunnels.go`: 40 simulated tunnels on the simulated agents (1–3 each), in every type and state (ACTIVE, GRACE) | phases 1, 6 and 7 |

- **Distributions** follow the mock-data rules' patterns: the first 60%
  ACTIVE and the next 20% GRACE, cycling after that.
- **Before any FK is validated**, the generators check that the referenced
  phase has already run.
- **Build check:** `go build ./tests/mocks/` and `go vet` pass.

### 7.5 Migrating today's deployment

1. Run the new `l8tunnel-server export --db /var/lib/l8tunnel/l8tunnel.db
   --out export/` on k8s-node-2. It writes tokens (IDs, hashes, policies,
   certificate serials), reservations and gateway keys as JSON, plus the
   agent CA as PEM files (mode 0600).
2. `k8s/secrets.sh` loads the agent CA and newly generated cluster and OIDC
   keys. It optionally loads the TLS certificate as the first-start
   `l8tunnel-tls`.
3. Deploy, then import through `TunIssue IMPORT` (the UI's data-import page
   or `go/tun/tools/import`).
   - In Edge ▸ Domains, upload the Porkbun `layer8-tunnel.info` bundle on the
     `TUNNEL_BASE` row. The relays and the edge switch to it without a
     restart.
   - Add the `admin.layer8-tunnel.info` row (`443 → 5443`, LAN-only).
4. `systemctl disable --now l8tunnel-server` on k8s-node-2, so the edge can
   bind 80/443. The ufw rules stay as they are.
5. The agents (the laptop `x1` and the others) reconnect with the same
   tokens, names and ports. Nothing changes on the agents.

## 8. Wire compatibility

No changes to `proto/l8tunnel.proto`, the ALPNs, `connect.<base>` or the
token format. Existing agent and client binaries work against the cluster
unchanged. Phase K7 checks this with the **already-built** agent packages
(version `5b19bbc`).

## 9. Duplication audit

| # | Existing code | Overlap with this plan | Decision |
|---|---|---|---|
| 1 | `tunnel/relay/peek.go`: unexported ClientHello peek and replay (`prefixConn`, including the `WriteTo` fix) | The edge needs the same thing | **Phase K0:** extract to `tunnel/sni`, used by the relay and the edge. Never copy it (Second Instance Rule) |
| 2 | `tunnel/pipe` (bidirectional copy with half-close) | Edge L4 forwarding and relay-to-relay forwarding | Reuse as is |
| 3 | `tunnel/relay/registry.go` (claim, park, reserve, ports, domains, grace) | `TunLive.Before()` enforces the same rules cluster-wide | **K0:** move the pure rules (conflict checks, port allocation, max_tunnels, grace math) into `tunnel/registry` functions that take state as arguments; the in-memory registry and the `TunLive` callback both call them |
| 4 | `tunnel/store` (bbolt) and the admin API validation | The ORM callbacks validate the same objects | **K0:** keep validation in `auth` (policy, names, domain patterns, gateway grants); the admin API and the callbacks call it. The bbolt store becomes the standalone `relay.Accounts` |
| 5 | `l8web/go/web/proxy` (about 440 lines): an SNI-based TLS-terminating reverse proxy | The edge TERMINATE mode covers the same job | **Assessed for porting (2026-09-25); not ported.** Findings:<br>• It only terminates TLS: no L4 passthrough, which RELAY and PASSTHROUGH need.<br>• One backend per domain (`NODE_IP:port`): no pools, health checks or retries.<br>• Routes are hardcoded in Go.<br>• It re-reads certificate files on every handshake, and unknown SNIs get the first route's certificate.<br>• Its catch-all handler builds a new proxy and transport per request, so there's no connection reuse.<br>• HTTP/1.1 only, with `InsecureSkipVerify` always on and no `X-Forwarded-*` headers.<br>• A hand-rolled WebSocket forwarder that ignores errors (the standard reverse proxy handles upgrades).<br>• No timeouts, a log line per request, and 502 for unknown hosts.<br>l8tunnel's `httpproxy` and `certs` already do this job better (§3.7), so reusing them is less work than porting and fixing.<br>**Taken from it:** its Kubernetes manifest (`proxy.yaml`, a hostNetwork DaemonSet) as a reference for the edge YAML, and its domain → port table as the first `EdgeDomain` rows and port forwards if the other sites move onto the edge (§3.1 example, §12).<br>l8web itself isn't changed (FrameworkInterfaceBoundaries). It's flagged to the framework owner as a candidate to retire once the edge carries those sites |
| 5a | `tunnel/httpproxy` and `tunnel/certs` (the relay's HTTP termination and certificates) | The edge TERMINATE mode | **Reused (§3.7):** the edge pool implements `httpproxy.Tunnel`. Additions: 503 for no healthy member, `UpstreamTLS`, and `certs.ModeStaticSet`. No copy of either package |
| 6 | Relay HTML error pages (`httpproxy/pages.go`) | The edge's 503 "no healthy backend" page | The edge imports `httpproxy`'s page renderer |
| 7 | The request inspector UI (plain HTML, agent-side) | None: the agent's local tool, not the management app | Out of scope, unchanged |
| 8 | l8ui sections (UI) | 10 sections of config-only files | Data only; custom behavior limited to two show-once handlers sharing one `sections/tun-show-once.js` helper (desktop, plus its mobile twin) |

- **Behavioral-lines check:** items 1, 3 and 4 are above the
  `behavioral_lines × instances > 100` threshold, so Phase K0 extracts them
  before anything else is built.
- **Platform check:** each UI component has a desktop and a mobile row in §6
  and in the matrix (Component × Platform).

## 10. Phases

Each phase ends with `go build ./...`, the whole existing suite (106+ tests,
with `-race`), and the phase's new tests green. Each phase is committed only
when you ask.

**K0 — Refactor and spikes (no behavior change)**

- Extract `tunnel/sni`, `tunnel/registry` rules, the `relay.Accounts` and
  `relay.Registry` interfaces, and the `auth` validators.
- Add `/healthz`, `/readyz` and `/metrics` on one listener.
- Add PROXY v2 read support behind `trusted_proxies` (standalone too).
  Library `github.com/pires/go-proxyproto`, added through `vendor.sh`.
- Spikes:
  1. An in-memory (non-ORM) l8services service in the registry process, with
     Before hooks and re-announce by multicast, for `TunLive`.
  2. Change-notification subscription from a non-owner vnic.
  3. `common.GenerateID` semantics on a preset ID, for import.
  4. Vnet, web and log ports free on the shared cluster.
  5. l8ui editing of a child list inside a child row. **Outcome:** not
     supported (§16.6), so targets are a tags field.
- Record the outcomes in this plan before K1.

**K1 — Model and management backend**

- `proto/tun.proto` and bindings.
- `go/tun/common`; the ORM services and callbacks (access, edge domains
  with port forwards and certificate validation, alerts); `TunIssue`;
  `EdgeNode`; the `simulated` flag and its rules.
- The FileStore permission rules; FileStore itself runs in the web process
  (§16.4). Creating the `TUNNEL_BASE` row at first start.
- The listener services `TunRlyCtl` and `EdgeCtl`, and the owners'
  `After()` multicasts to them (§16.2).
- The security config JSON in l8secure (sysconfig ports from §16.5, roles,
  deny rules); `go/tun/main` and `go/tun/vnet`.
- Registering events and notify types.

**K2 — Relay cluster mode**

- `tunnel/cluster`: `Accounts` over vnic with a snapshot, and `Registry` over
  `TunLive`.
- The registry process (`go/tun/registry`) as the single owner of
  `TunLive`/`TunAgent`/`TunRelay`; heartbeats, lost-relay cleanup, agent
  records with batched heartbeat updates and the 24 h offline retention, and re-announce
  after a registry restart.
- Internal listeners 8443, 8080 and 8444 with PROXY v2 and TLVs; relay-to-relay
  forwarding with HMAC.
- Cross-relay takeover and grace; drain; cluster config and fail-fast checks
  (admin socket off, no ACME).
- The relay loads the `TUNNEL_BASE` certificate from FileStore, reloads it
  on change, and keeps a local copy (§4.1).
- Relay events; the `export` command; `go/tun/relay/main.go`.

**K3 — Edge**

- `tunnel/edge`: listeners derived from the domain table, opened and
  closed live (§3.2); route resolution on shared ports (§3.3); modes RELAY,
  PASSTHROUGH and TERMINATE; protocols TLS, HTTP and TCP. TERMINATE is built on `httpproxy` through
  `edge/pool.go` implementing `httpproxy.Tunnel` (§3.7).
- `httpproxy` additions (503 for no healthy member, `UpstreamTLS`) and
  `certs.ModeStaticSet`, with the relay's existing tests still green.
- Pools, LB algorithms, active and passive health, and retry before the
  first byte.
- PROXY v2 writer, per-IP rate limits and per-domain IP lists.
- Certificate loading from FileStore into `certs.ModeStaticSet`, and the
  domain and certificate cache.
- `EdgeNode` reporting (listeners and backends), metrics and events;
  `go/tun/edge/main.go`.

**K4 — Alerts and notifications**

- The evaluator, the conditions in §5.5, cooldowns, certificate expiry from
  every `EdgeDomain`, and listener failures.

**K5 — Management UI**

- The desktop and mobile sections in §6, dashboard, realtime tables, the
  show-once handlers, the agent status screen (Tunnels ▸ Agents), Drain /
  Disconnect actions, and the SYS, Events and
  Notify sections.
- `login.json`, the reference registry, and verifying the script order.

**K6 — Deployment, local run, mock data**

- Every Dockerfile and `build.sh`, base images, `build-all-images.sh`, the
  four k8s modes, the KIND scripts, `deploy.sh`/`undeploy.sh`, `secrets.sh`,
  `label-edge.sh`.
- `log-vnet` and `log-agent`, `run-local.sh`, and the `go/tests/mocks`
  generators for all 11 services in 8 phases (§7.4), including simulated agents,
  relays, edge nodes and tunnels.
- Import tool; PRD and README updates.

**K7 — Go end-to-end verification (`go/tests/`)**

- **Cluster tests in process:** a vnet, the backend services, the
  registry, two or three relays and an edge, with real agents.
- **Coverage:**
  - load balancing of agents
  - owner routing for HTTPS, passthrough, mode A and mode B
  - forwarding on a stale table
  - takeover and grace across relays
  - drain and relay loss
  - revocation propagation
  - PROXY client IP reaching the IP lists and `X-Forwarded-For`
  - HMAC spoof refusal
  - the edge TERMINATE and PASSTHROUGH pools with health ejection
  - Edge domains:
    - a new port forward opens a listener, and deleting it closes one
    - a port that can't bind is reported, not fatal
    - two domains share 443 by SNI; a TCP port conflict is refused
    - uploading a certificate that doesn't match or cover the domain is
      refused
    - a certificate replaced in the UI is served without a restart
    - a private key can't be downloaded by operators or viewers
  - Load balancing: the distribution matches the weights within ±5 % over
    1,000 connections; a failed member is ejected and comes back; a disabled
    member gets nothing; source hash keeps a client on one member; least
    connections follows the active-connection counts; TERMINATE balances
    per request over keep-alive connections
  - TERMINATE: h2 and WebSocket through the edge, connection reuse to the
    backend, upstream certificates verified by default, unknown SNI
    refused, and certificate reload after a Secret change
  - management-plane-down resilience
  - registry restart: re-announce, no dropped tunnels, and claims resuming
  - agent records: version, OS, transport and IP (through the edge) match
    the real agent; the RTT updates; takeover on another relay moves the
    record; each disconnect reason is recorded; offline records expire;
    Disconnect agent closes every tunnel of the session and the agent
    reconnects
  - simulated records never routed to
  - the §5.7 separation: an agent token refused by the management API, a
    management bearer token refused as an agent credential
  - `TunIssue` show-once
  - the import round trip
  - alert delivery through Notify
- **Old agent binaries:** a real-binary smoke run with the `5b19bbc` agent
  packages.
- **Compliance greps** (§14).

**K8 — Browser E2E on KIND (PostImplementationE2ETesting), then final verification**

- `e2e/` Playwright suite (`fixtures/`, `pages/`, `tests/desktop/`,
  `tests/mobile/`) against `kind-start.sh`.
- For every section: navigate, data loads, row click, forms submit, the
  show-once popups, and realtime row updates when an agent connects or
  disconnects. Each spec cleans up after itself and asserts on presence,
  not counts.
- Then **production cutover** on the real cluster (§7.5), watched live:
  - the laptop agent's `x1` SSH and `x1-web` from outside (hotspot)
  - management UI login from the LAN, and refused from outside
  - a relay pod deleted with agents moving and names kept
- Write `plans/k8s-verification.md` in the format of the earlier verification
  reports.

## 11. Traceability matrix

Platforms:

| Platform | Meaning |
|---|---|
| Go-edge | The edge proxy |
| Go-relay | The relay in cluster mode |
| Go-mgmt | The management backend |
| Desktop | Desktop UI |
| Mobile | Mobile UI |
| K8s | All four modes |
| Standalone | The systemd relay |

| # | Section | Gap / Action Item | Platform | Phase |
|---|---|---|---|---|
| 1 | §9.1 | Extract ClientHello peek to `tunnel/sni` | Go-relay, Go-edge | K0 |
| 2 | §9.3 | Extract registry rules to `tunnel/registry` | Go-relay, Go-mgmt | K0 |
| 3 | §9.4 | `relay.Accounts`/`relay.Registry` interfaces; shared `auth` validators | Go-relay, Standalone | K0 |
| 4 | §4.3 | Health/readiness/metrics endpoints | Go-relay, Standalone | K0 |
| 5 | §3.5 | PROXY v2 reader with `trusted_proxies` | Go-relay, Standalone | K0 |
| 6 | §4.2 | Spikes: registry in-memory service, subscriptions, GenerateID, ports | Go-mgmt | K0 |
| 7 | §5.2 | `proto/tun.proto`, enums, List types, bindings | Go-mgmt | K1 |
| 8 | §5.3 | TunToken, TunResv, TunGwKey, TunAgCert services and callbacks | Go-mgmt | K1 |
| 9 | §5.3 | TunIssue (token, certificate, import) | Go-mgmt | K1 |
| 10 | §5.3 | EdgeDomain (port forwards, certificate validation via FileStore, TUNNEL_BASE row) and EdgeNode services; `simulated` flag rules | Go-mgmt | K1 |
| 10a | §5.6 | FileStore activation in the backend; upload and download permissions (no key download for operators and viewers) | Go-mgmt | K1 |
| 11 | §5.6 | Security config JSON, sysconfig ports, roles, deny rules, FileStore rules | Go-mgmt | K1 |
| 11a | §16.2 | Listener services TunRlyCtl and EdgeCtl, owners' After() multicasts, 60 s re-read | Go-mgmt, Go-relay, Go-edge | K1, K2, K3 |
| 12 | §5.4 | Events types registered; backend events | Go-mgmt | K1 |
| 13 | §4.1 | Accounts over vnic with a snapshot; revocation propagation | Go-relay | K2 |
| 14 | §4.2 | Registry as single owner of TunLive/TunAgent/TunRelay: claims, port allocation, takeover, grace, lost relay, re-announce | Go-relay | K2 |
| 14a | §4.2a | TunAgent records: login data, batched heartbeats, states and disconnect reasons, 24 h offline retention, disconnect-agent action | Go-relay, Go-mgmt | K2 |
| 15 | §4.3 | Internal listeners 8443/8080/8444 | Go-relay | K2 |
| 16 | §4.4 | Relay-to-relay forwarding with TLV + HMAC, no second hop | Go-relay | K2 |
| 17 | §4.5 | Drain (UI and preStop), paced session close | Go-relay | K2 |
| 18 | §4.6 | OIDC/custom-domain/admin-socket rules in cluster mode; fail-fast | Go-relay | K2 |
| 19 | §7.5 | `l8tunnel-server export` | Standalone | K2 |
| 20 | §3.2 | Listeners derived from port forwards, opened and closed live; bind failures reported; bootstrap TUNNEL_BASE ports | Go-edge | K3 |
| 21 | §3.3 | Route resolution on shared TLS/HTTP ports, TCP ports by port, stale-table fallback | Go-edge | K3 |
| 22 | §3.1 | RELAY, PASSTHROUGH, TERMINATE modes; TLS, HTTP, TCP protocols; target kinds | Go-edge | K3 |
| 22a | §3.7 | TERMINATE on `httpproxy` (pool as `httpproxy.Tunnel`); `httpproxy` 503 and `UpstreamTLS`; `certs.ModeStaticSet` | Go-edge, Go-relay | K3 |
| 23 | §3.4 | Per-port-forward pools of weighted `ip:port` targets; weighted round robin, least connections, consistent source hash, random; active and passive health, retry | Go-edge | K3 |
| 24 | §3.5 | PROXY v2 writer, edge rate limits, per-domain IP lists | Go-edge | K3 |
| 25 | §3.6 | Certificates from FileStore, domain and certificate cache, bootstrap config, EdgeNode reporting, metrics | Go-edge | K3 |
| 25a | §4.1 | Relays serve the TUNNEL_BASE certificate from FileStore, with live reload | Go-relay | K2 |
| 26 | §5.5 | Alert rules, evaluator, Notify().Send, cooldown | Go-mgmt | K4 |
| 27 | §6 | Dashboard | Desktop | K5 |
| 28 | §6 | Dashboard | Mobile | K5 |
| 29 | §6 | Tunnels (Agents status screen, Live, Relays, Edge nodes) with actions | Desktop | K5 |
| 30 | §6 | Tunnels (Agents status screen, Live, Relays, Edge nodes) with actions | Mobile | K5 |
| 31 | §6 | Access (Tokens + issue, Reservations, Gateway keys, Agent certs + issue) | Desktop | K5 |
| 32 | §6 | Access (Tokens + issue, Reservations, Gateway keys, Agent certs + issue) | Mobile | K5 |
| 33 | §6 | Edge ▸ Domains (table, certificate upload, port forwarding inline table) and Edge ▸ Router ports | Desktop | K5 |
| 34 | §6 | Edge ▸ Domains (cards, certificate upload, port forwarding cards) and Edge ▸ Router ports | Mobile | K5 |
| 35 | §6 | Alerts ▸ Rules | Desktop | K5 |
| 36 | §6 | Alerts ▸ Rules | Mobile | K5 |
| 37 | §6 | System, Events, Notify sections; login.json; reference registry | Desktop | K5 |
| 38 | §6 | System, Events, Notify sections; login.json; reference registry | Mobile | K5 |
| 39 | §7.1 | Dockerfiles, build.sh, base images, build-all-images.sh | K8s | K6 |
| 40 | §7.2 | Four k8s modes, KIND scripts, deploy/undeploy, secrets.sh, label-edge.sh | K8s | K6 |
| 41 | §7.1 | log-vnet and log-agent binaries, images, YAML entries | K8s | K6 |
| 42 | §7.3 | run-local.sh, PRD "Local Development Setup" | Go-mgmt | K6 |
| 43 | §7.4 | Mock generators for all 11 services (8 phases, simulated live records) + demo agent | Go-mgmt | K6 |
| 44 | §7.5 | Import tool | Go-mgmt | K6 |
| 45 | §10 | Go end-to-end cluster tests | Go-edge, Go-relay, Go-mgmt | K7 |
| 46 | §8 | Old agent packages against the cluster | Go-relay | K7 |
| 47 | §1 | Standalone regression (whole existing suite) | Standalone | every phase, K7 |
| 48 | §10 | Playwright E2E | Desktop | K8 |
| 49 | §10 | Playwright E2E | Mobile | K8 |
| 50 | §7.5 | Production cutover on k8s-node-2 and verification report | K8s | K8 |
| 51 | §5.7 | Data-plane / management-plane security separation and its tests | Go-relay, Go-mgmt | K1, K7 |
| 52 | §7.1 | Registry image, build.sh, YAML in all four modes | K8s | K6 |
| 53 | §15 | Rule exceptions recorded in the PRD | Go-mgmt | K6 |

## 12. Deferred, with reasons

| Item | Why deferred | Path later |
|---|---|---|
| ACME in cluster mode (on-demand certificates for HTTP-terminated custom domains, automatic wildcard renewal) | Needs certmagic storage shared across relays, with locking. Today's deployment uses a static Porkbun wildcard, so nothing regresses | A certmagic `Storage` backed by a Layer 8 service, or a cert-manager Secret; `CERT_EXPIRING` alerts cover renewal until then |
| Edge HA | The router forwards to one IP. HA needs a floating VIP and a router change | kube-vip/keepalived VIP on two edge nodes; the edge is already stateless apart from its cache |
| Agent pools (one name, several agents, load-balanced) | New semantics for names and takeover | `TunLive` records per agent under one name, and a pick at the owner relays |
| Moving the other Layer 8 sites (probler.dev, l8erp.one, ...) off the `l8web` proxy | Not needed for l8tunnel. Each move is one `EdgeDomain` row with its certificate upload and port forwards (§3.1 example), done in the UI, with no code change | Add the rows once the edge is live, and forward each listed port on the router (Edge ▸ Router ports) |

## 13. Decisions I made for you (change any before approving)

1. **Edge placement:** pinned to k8s-node-2 by the label
   `l8tunnel.io/edge=true`, since the router forwards to 192.168.1.120.
2. **Relay replicas:** 2.
3. **`TunLive` hosting:** a dedicated single-replica registry process, the
   sole owner (SingleOwnerDatabaseTable). It has no database, so the data
   plane doesn't depend on the management backend.
4. **Management UI:** `admin.layer8-tunnel.info` through the edge, LAN-only
   by default.
5. **Service areas:** 40 access, 41 edge, 42 live, 43 alerts. API prefix
   `/tun`, Go module directory `go/tun`, namespace and image prefix
   `l8tunnel`.
6. **Other sites through the edge:** supported (§3.3), but none are added by
   this plan.

## 14. Compliance checklist

| Rule | How this plan complies | Checked in |
|---|---|---|
| PrdCompliance | l8erp layout for all new code (§5.1), existing packages exception X-4; this checklist | K7 walk |
| PlanRequirements | Written to `./plans/`, waiting for approval; duplication audit §9 with Phase K0; Component × Platform matrix §11; final E2E phase K8 | — |
| CanonicalProjectSelection | l8erp (CRUD configuration); the probler pattern ruled out (§5) | — |
| ArchitectureOverview / AppHtmlBodyFromL8erp / IndexHtmlRedirect | l8erp shell, `index.html` redirect, config-driven sections | K5, K8 |
| AddingModule (desktop and mobile steps) | Every section in §6 on both platforms | K5 |
| MobileRules (parity) | Mobile row for every component (§11) | K8 mobile specs |
| ScriptLoadingOrder / VerifyAppHtmlScriptsAgainstLoadingOrder / PrdL8uiIncludesAudit | Canonical order, grep check, startup dependency check | K5 |
| FailFastNoSilentFallback / ReportInfraBugs | Startup dependency check; relay and edge config fail fast (cluster mode refuses admin socket and ACME) | K2, K3, K5 |
| L8UIThemeCompliance / L8UINoProjectSpecificCode / L8UICopyToNewProject | `--layer8d-*` only; l8ui as a submodule, unchanged | K5 |
| EnumRendererColumnCascade / JsProtobufFieldNames / SharedComponentsReference | Enum factory, renderers and column factory for every enum; camelCase JSON names | K5 |
| ReferenceRegistryCompleteness | Registry entries for every Prime Object | K5 grep |
| InlinePopupRenderingParity / StackedPopupDomScoping | Show-once popups through Layer8DPopup / Layer8MPopup | K5, K8 |
| ImmutabilityUiAlignment | `TunLiveTunnel`, `TunAgent`, `TunRelay`, `EdgeNode` read-only in the UI (actions only) | K5 |
| Layer8DTablePaginationMetadata / L8QueryRules | Counts on `page 0`; every GET with L8Query; `select *` for detail popups | K5 |
| SpecialCases (read-only services, custom handlers) | Live services read-only; Issue as custom handlers | K5 |
| ProtobufRules | UNSPECIFIED zero values, `list=1`/`metadata=2`, type names in JS, `make-bindings.sh` with `-i` | K1 grep |
| PrimeObjectReferences | Children embedded; references by ID only (§5.2) | K1 review |
| Maintainability (≤500 lines, split at 450; ServiceName ≤10; area per module; GenerateID in Before POST; UI type registration; duplication) | §5.2 names are 7–9 characters; callbacks generate IDs; K0 extractions | K7 greps |
| MainPackageMinimal | Each `main.go` only wires resources, vnic, Activate and waits | K7 review |
| NoGoGenerics | None | K7 grep |
| FrameworkInterfaceBoundaries | No changes to `l8types/go/ifs`; existing extension points (ServiceCallback, IServiceCacheListener) | K7 review |
| SingleOwnerDatabaseTable | Every service has exactly one owner process (§5.2): ORM services in the backend; `TunLive`/`TunAgent`/`TunRelay` in the registry; `EdgeNode` in the backend. Relays, edge and UI only use vnic | K7 grep for `Activate` per `main.go` |
| SecurityRules / SecurityConfigStructure / AssociateIdsScopeView | Management plane: ISecurityProvider only; config JSON in l8secure; users via area 73; no l8secure import; no field deny (§16.15). Data plane: §5.7 boundary, exceptions X-1 and X-2, both approved (§15) | K1, K7 grep and separation tests |
| EventsServiceRequired | Never activated by the project; `EventRecord` registered; events §5.4 | K1, K7 grep |
| NotifyServiceRequired | `Notify().Send` only; types registered; no `net/smtp` or Slack code | K4, K7 grep |
| LogServicesRequired / L8Logs | log-vnet and log-agent in every artifact list; LOGPATH `/data/logs/l8tunnel`; the SYS log viewer | K6 |
| DeploymentArtifacts | §7.1; every new image on the own `-security`/`-postgres` base images; standalone images are exception X-5 | K6 |
| K8sRules | §7.2; the rule's verify greps | K6 |
| RunLocalScript | §7.3 | K6 |
| MockDataRules | §7.4: generators for all 11 services in 8 dependency-ordered phases (live services through simulated records), endpoints `/tun/<area>/<ServiceName>`, users through area 73 | K6 |
| FileUploadPattern | Certificate and key uploaded through `FileStore` and `Layer8FileUpload` (`f.file`); `EdgeDomain` stores only `*_storage_path`, `*_file_name`, `*_file_size`; no file I/O in callbacks (files fetched through FileStore over vnic); 5 MB limit is ample for PEM | K1, K5, K7 |
| TestLocationAndApproach / CleanupTestBinaries | Tests only in `go/tests/`, through system APIs; built test binaries removed | K7 |
| PostImplementationE2ETesting | `e2e/` Playwright on KIND, desktop and mobile, hygiene rules | K8 |
| VerifyPrdCompletenessBeforeDone | Section-by-section walk in the K8 report | K8 |
| LoginJsonAdaptation / SetupConfiguration / ModconfigFailureNoLogout | `login.json` adapted (§6); ModConfig failures don't log out | K5 |
| PortalsSameWebServer | One UI server, one portal | K6 |
| VendorAndGit | Dependencies only through `vendor.sh`; `go/vendor/` untracked; git only when asked | every phase |
| NeverActOnQuestions | Followed | — |
| Not applicable | L8Pollaris*, DataCompletenessPipeline, MoneyFieldTypeMapping, DateField pipeline beyond timestamps, RegistrationPage (admins provision users), LoginableEntityUserProvisioning, L8AgentChat, Layer8CsvExport (optional, not planned), DemoDirectorySync, PlatformConversionDataFlow (no platform conversion) | — |

**Also kept from the l8tunnel PRD §13.2:** no ignored errors, gofmt,
`dist/` and `.pem` files never committed, and Secrets never committed.

## 15. Rule exceptions

Every place this plan departs from a guideline, stated explicitly.
Everything not listed here complies.

| # | Rule | Exception | Scope | Why | Status |
|---|---|---|---|---|---|
| X-1 | SecurityRules (all AAA through `ISecurityProvider`) | Agent ↔ relay authentication (agent tokens and mTLS agent certificates) is done by the relay, not `ISecurityProvider` | `go/tunnel/auth`, the relay's control path | A wire-protocol credential for machines, checked on the hot path and needed while the management plane is down. Issuing and revoking these credentials stays under `ISecurityProvider` (§5.7) | **Approved by you** (2026-09-25) |
| X-2 | SecurityRules | Tunnel-visitor access control (IP lists, basic auth, OIDC login cookies, SSH access tokens) and SSH gateway keys are done by the relay | `go/tunnel/auth`, `oidc`, `httpproxy`, the relay gateway | Anonymous internet clients of the operator's customers, not Layer 8 users; the policies come from the tunnel owner's `Register` message. Bounded as in §5.7 | **Approved by you** (2026-09-25, covered by the X-1 waiver) |
| X-3 | SingleOwnerDatabaseTable, intent | None any more: `TunLive`/`TunAgent`/`TunRelay` now have one owner, the registry (§4.2) | — | Resolved by design | Resolved |
| X-4 | PrdCompliance (l8erp layout) | The existing `go/cmd/*` binaries and `go/tunnel/*` packages keep their layout; only new code follows `go/tun/…` | Existing standalone and data-plane code | They are the standalone product and the shared data-plane library, built by the release tarballs, the Dockerfile and the install packages; moving them would break those for no gain | **Approved by you** (2026-09-25) |
| X-5 | DeploymentArtifacts (own `-security`/`-postgres` base images) | The root `Dockerfile`'s standalone `server`/`agent` images stay distroless | Standalone images only | They never join a vnet or load a security plugin, and aren't part of any Kubernetes deployment in this plan. Every new image uses the base images | **Approved by you** (2026-09-25) |
| X-6 | RunLocalScript (`go/run-local.sh`) | No local run script and no demo agent (§7.3) | The whole project | Not needed: the cluster is developed and tested in KIND | **Waived by you** (2026-09-26) |

All six are copied into the PRD in K6, so the exceptions stay visible
after this plan is done.

## 16. K0 outcomes (recorded 2026-09-25, before K1)

### 16.1 Code delivered in K0 (no behavior change for existing setups)

| Item | Result |
|---|---|
| `tunnel/sni` | The ClientHello peek moved out of the relay into its own package. It works on any `net.Conn`, keeps the replay-safe `WriteTo`, and adds `ReadFrom` so TCP writes keep the splice fast path |
| `tunnel/registry` | The name, reservation and port rules and the claim decision (new, reclaim, takeover) moved out of the relay. The relay calls them, and the `TunLive` callback will call the same code. Error messages are unchanged |
| PROXY protocol | `transport.ProxyProtocolListener` wraps every relay listener: control, HTTP, SSH gateway and mode A ports. Headers are used only from `trusted_proxies`, refused from anywhere else, and not parsed at all when none are configured. Library `github.com/pires/go-proxyproto` v0.15.0 |
| Health | `OpsHandler`: `/metrics`, `/healthz`, `/readyz` on the `metrics.listen` address |
| Tests | 6 new end-to-end tests (PROXY from trusted and untrusted sources, mode A behind a proxy, no parsing without trusted proxies, probes, config) plus the whole existing suite, green with `-race` |
| Deferred to K2 | The `relay.Accounts` / `relay.Registry` interfaces are introduced together with their first cluster implementation, not ahead of it. Defining them with no second implementation would have been speculative code |
| Small fix | `Reserve` now also refuses the OIDC login host's name, as tunnel registration always did |

### 16.2 Pushing changes to relays and edges

Spike 2 found that Layer 8 has no subscription mechanism for a process that
doesn't own a service:

- Built-in notifications only reach processes that activate the same
  service.
- ORM services don't notify peers at all.

The design therefore uses the l8pollaris pattern (`TargetCallback`
multicasting to its collectors):

- Two **listener services** carry the changes: `TunRlyCtl` (area 42) in
  every relay, and `EdgeCtl` (area 41) in every edge. They are stateless,
  with no store and no UI.
- The owners (the backend's ORM callbacks and the registry's callbacks)
  call `vnic.Multicast(listener, area, action, elem)` in `After()` when the
  change isn't itself a notification.
- The listeners apply each change to their local copy. Examples: a token
  deleted means its sessions are dropped; a takeover elsewhere means the
  stale session is closed; a drain request starts the drain; an
  `EdgeDomain` change reloads routes and certificates.
- **Resync.** At startup, and every 60 s, relays and edges re-read
  everything with `vnic.Request` GETs. A lost multicast is therefore healed
  within a minute. Revocation still takes effect immediately in the normal
  case.

### 16.3 Security model between processes

Spike 6 found how l8secure treats processes:

- Processes join the vnet by proving the project's shared secret, encrypted
  with the project key.
- Their requests carry a short alias ID, and l8secure's `CanDoAction`
  allows those without role checks. Roles are checked only for UI users
  coming through l8web bearer tokens.

What that changes in the plan:

- No `relay`, `edge`, `registry` or `mock` roles. Vnet membership is the
  trust boundary between processes. The vnet ports (§16.5) are never
  forwarded on the router.
- `simulated` records are gated by the `L8TUNNEL_ALLOW_SIMULATED=true`
  environment variable on the owning process (set only by `run-local.sh`
  and the KIND manifests), not by a role.
- `secretHash` is a bcrypt hash of 32 random bytes; the UI never shows it.
  The field-deny rule planned for it was removed in K7 (§16.15).

### 16.4 FileStore

Spike 5 found:

- **Where it runs.** `filestore.Activate` is called by l8common's
  `CreateWebServer`, so FileStore runs in the **web UI process** and stores
  files under that process's `/data/l8files`.
- **Sizes and paths.** Uploads are limited to 5 MB. The POST returns
  `storagePath`, `fileName`, `fileSize`, `mimeType` and `checksum`; the PUT
  downloads by `storagePath`.
- **Access control.** It is action-level only, on the message types
  `L8FileUploadRequest` and `L8FileDownloadRequest`. There is no per-file
  ACL.

What that changes in the plan:

- **One web instance.** The web UI (and so FileStore) must be a single
  instance, or files would land on whichever node took the upload.
  `l8tunnel-web` is pinned with the edge's node label in every mode (§7.1),
  and the backend doesn't activate FileStore itself.
- **Certificate files.** The `EdgeDomain` callback accepts only storage
  paths under `/data/l8files/edgecert/`, and uploads use that document ID.
- **Framework bugs to report** (ReportInfraBugs, not fixed here: l8services
  isn't this project's code):
  1. `FileStorePost` doesn't sanitize `fileName` / `documentId`, so `../`
     can write outside the storage root.
  2. `FileStorePut`'s prefix check has no trailing separator, so
     `/data/l8files2/...` passes.

  Until they're fixed, the upload permission stays admin-only.

### 16.5 Ports (none collide with probler or l8erp)

| Component | Port | Notes |
|---|---|---|
| l8tunnel vnet | 29000 TCP, and 28998 UDP (discovery is always vnet port − 2) | probler uses 26000/25998, l8erp 48884/48882 |
| l8tunnel log vnet | 29010 TCP, and 29008 UDP | probler 27000, l8erp 48891 |
| l8tunnel web UI | 5443 | probler 2443, l8erp 2773 |
| Edge public ports | 443, 80, 22000–22999, 2222, plus any added in Edge ▸ Domains | 443/80 are currently held by the systemd relay on k8s-node-2 (§7.5 step 4) |

- **Where the ports are set.** They go in the `sysconfig` of
  `l8secure/go/secure/plugin/l8tunnel/l8tunnel.json` (`vnetPort`,
  `logConfig.vnetPort`, `webConfig.webPort`). Layer 8 has no environment
  variable or flag for them.
- **YAML note.** The `containerPort` values in the probler and l8erp YAMLs
  don't match their real ports; with `hostNetwork` they have no effect.
  l8tunnel's YAMLs list the real ones.

### 16.6 l8ui: editing a list inside a child row

Spike 5 (l8ui) found that a child list inside an inline-table row can't
be edited today, on desktop or mobile:

- The row editor renders the nested table but never wires its buttons.
- No project edits a grandchild list.

What that changes in the plan:

- **Targets as tags.** `EdgePortForward.targets` is a `repeated string` of
  `host:port[*weight]` entries (`!` prefix disables one), edited with
  `f.tags`, which works on both platforms today. The callback parses and
  validates every entry and rejects bad ones with a clear message. There is
  no `EdgeTarget` message.
- **Framework limitation to report:**
  - mobile: `_openMobileRowEditor` should pass `miniFormDef` to
    `initFormFields`
  - desktop: `openRowEditor`'s `onShow` should attach inline-table handlers
    that look up fields in the mini form

### 16.7 Other answers

- **ID generation.** `common.GenerateID` keeps a preset ID, so import keeps
  token IDs through a plain POST.
- **In-memory services.** They use `base.BaseService` with
  `ifs.NewServiceLevelAgreement(..., stateful=true, callback)`,
  non-transactional, and `sla.SetWebService(web.New(...))` for REST. This
  is the pattern of the l8bus Health service.
  - L8Query GETs are served from the cache without calling the callback.
  - Realtime tables work, because non-transactional services multicast the
    websocket notifications.
- **Calling services.** Timeouts on `vnic.Request` are in seconds.

### 16.8 Open question: where the cluster runs

k8s-node-2 (192.168.1.120) runs **no Kubernetes**: no kubelet, containerd,
Docker or kubectl. It only runs the systemd relay and sshd.

- The one non-KIND context in this laptop's kubeconfig
  (`kubernetes-admin@kubernetes`, 192.168.86.223:6443) isn't reachable.
- KIND works locally, which is enough for K1–K8 development and the
  browser tests.

**Before the K8 production cutover, you need to decide one of:**

- install Kubernetes on k8s-node-2 (and any other nodes)
- point the router at an existing cluster's node
- run the cluster elsewhere

### 16.9 K1 findings and decisions (2026-09-25)

- **ORM deletes run no callbacks.** l8orm's `OrmService.Delete` never calls
  the service callback, so a plain DELETE can't be refused or pushed to the
  relays.
  - Tokens are therefore revoked through `TunIssue` with the new kind
    `REVOKE`. It deletes the token, its certificates and its reservations,
    and pushes the revocation to the relays at once. The UI's delete action
    for tokens uses it.
  - Other deletes reach relays and edges at their 60 s re-read.
  - The backend re-creates the `TUNNEL_BASE` domain every minute if it's
    deleted.
- **Simpler children.** `TunTokenPolicy.ports` stays a `"min-max"` string
  and `TunGatewayKey.tunnels` a list of patterns, exactly as the standalone
  relay stores them. The planned `TunPortRange` and `TunGatewayGrant`
  children would add nothing.
- **Tests run against KIND only** (your decision).
  - The management-plane tests (`go/tests/kind_*_test.go`) call the REST
    API of a real deployment in KIND and skip unless `L8TUNNEL_KIND_URL`
    is set.
  - The relay and agent suite keeps running in process, as before.
- **Images follow the ecosystem pattern exactly** (your decision). Each
  Dockerfile copies only its `main.go` and builds the code fetched from
  GitHub, and each `build.sh` pushes to Docker Hub. So every KIND test
  round is: push the code, build the images, `kind-start.sh`, test.
- **Pulled forward from K6** because K1 needs them for its tests:
  - the vnet, backend and web images
  - `k8s/l8tunnel-kind.yaml` with those three
  - `kind-start.sh`/`kind-stop.sh`, `deploy.sh`/`undeploy.sh`, and
    `secrets.sh` (the agent CA Secret)
  - the web server's `main.go` with a placeholder page (the UI itself
    stays in K5)
- **Base images.** `saichler/l8tunnel-security` and
  `saichler/l8tunnel-postgres` are built with
  `../l8secure/build-images.sh l8tunnel amd64` from the security config
  `l8secure/go/secure/plugin/l8tunnel/l8tunnel.json`. That file is new in
  the l8secure repository and not committed there.

### 16.10 K2 design decisions (2026-09-25)

- **A claims engine instead of callbacks.** `tunnel/claims` is a
  mutex-guarded engine in the registry. It serializes every claim, so two
  relays can never hand out the same name, port or custom domain at once
  (a service callback can't make its check and the write atomic).
  - It reuses `tunnel/registry`'s rules.
  - It has no framework dependencies, so it is tested in process.
- **Relays write nothing directly.** They call the registry's `TunClaim`
  action service: claim, park, release, announce, heartbeat, agent up and
  agent down.
  - The engine mirrors its state into `TunLive`, `TunAgent` and `TunRelay`,
    which are read-only for clients and reconciled every 30 s.
  - The UI's disconnect, drain and resume go through a second action
    service, `TunCtl`. This replaces the planned DELETE and PATCH on the
    live tables.
- **`TunLiveTunnel` is keyed by tunnel name**, since names are unique
  cluster-wide. `tunnel_id` stays as a field.
  - New fields: `session_id` (takeover checks) and `access_token` (such
    tunnels get no public port, and gateway keys need an explicit grant).
- **Where the relay glue lives.** It is in `go/tun/relaynode`, not
  `tunnel/cluster`, so the data-plane library (`go/tunnel/*`) keeps no
  Layer 8 dependencies. The relay package defines a small `Cluster`
  interface; nil means standalone.
- **An unreachable registry doesn't stop agents.** Agents treat any refusal
  as final, so a registry that stays unreachable for 10 s makes the relay
  end the session instead of refusing. The agent reconnects with its normal
  backoff.
- **Cluster mode on the relay:**
  - no per-port listeners: mode A traffic arrives on the stream port,
    signed by the edge
  - no local grace holds: the registry holds names cluster-wide
  - the tunnel certificate comes from the TUNNEL_BASE domain through
    FileStore, with live reload
  - the SSH gateway host key comes from the `l8tunnel-cluster` Secret
    (the same on every relay)
- **KIND:**
  - The relays run on the pod network (two replicas on one node) and reach
    the vnet at `NODE_IP`.
  - Per-relay NodePort Services let the tests reach each relay until the
    edge exists (K3).
  - `secrets.sh` also creates the `l8tunnel-cluster` Secret (forward key
    and gateway host key) and never replaces it.

### 16.11 K2 findings (2026-09-26)

- **Service handlers can't keep their own state.** The framework creates
  handler instances itself, from the type name, so values set in a
  handler's fields are lost.
  - Handler state goes through `sla.SetArgs` and is read back from the SLA
    (`common.ActionStubs.Arg`).
  - The first KIND run caught this: the registry's and the relays'
    handlers had nil state.
- **Agent tokens are looked up live on the handshake.**
  - A token issued a moment before the agent connects is found at once,
    and a revoked one is refused at once, with no wait for the pushed
    refresh.
  - While the backend is unreachable the relay's cache answers, backing
    off for 30 s after a failed lookup.
- **A restarted process rejects older bearer tokens (l8secure).** A process
  that starts after a user logged in (here, a restarted registry) rejects
  that user's bearer token with "invalid Token", while processes that were
  running at login accept it. UI users must log in again after that
  process restarts.
  - This is an l8secure behavior, to report to the framework owner
    (ReportInfraBugs).
  - The KIND tests log in again after restarting the registry.
- **Verified in KIND** (8 test groups):
  - claims and live records, including agent version, transport and state
  - mode A through the owner's stream port with signed PROXY headers; a
    second hop and a bad signature are refused
  - mode B and HTTP forwarded by the other relay
  - names and ports held across relays during the grace period, and
    reclaimed through the other relay
  - the SSH gateway reaching a tunnel on the other relay
  - operator disconnect, drain and resume
  - revocation releasing names at once
  - a registry restart rebuilt from the relays' announcements

### 16.12 K3 decisions (2026-09-26)

- **The edge core is `tunnel/edge`**, a data-plane package with no Layer 8
  dependencies, tested in process against real backends and a real relay.
  The cluster glue is `go/tun/edgenode`: domains, certificates and the live
  tables in, `EdgeNode` reports out.
- **Listeners follow the domains.** A mode A range opens one listener per
  port, and they're reported as one range. A port that can't bind stays
  in the report with its error; it doesn't stop the edge.
- **Routing, as in §3.3.** An exact site name wins, then the control name
  (least-loaded ready relay), then a live tunnel (its relay), then a
  wildcard site, then any relay on a tunnel-base port. Unknown names get a
  TLS alert, or a 404 on HTTP ports.
- **Relays are chosen from the live tables, not from a pool:**
  - agents go to the ready relay with the fewest sessions
  - tunnels go to their owner
  - everything else round-robins across ready relays
  - draining relays are used only when nothing else is up
- **Pools:**
  - Algorithms: smooth weighted round robin, weighted least connections,
    rendezvous source hash (a client keeps its member, and adding a member
    moves only a share of the clients), and power-of-two random.
  - A failed dial marks the member suspect and moves to the next one, which
    is safe because no client byte has been sent.
  - Active checks are TCP or HTTP(S), every `health_interval` (default
    10 s); a member is down after 3 failures and back up after 2 passes.
- **TERMINATE uses `httpproxy` unchanged**, apart from the new
  `ErrUnavailable`, which the edge's pools return when no member is
  healthy (503 page `no-healthy-backend`). The TLS to https backends is
  done in the pool's `OpenStream`, so `httpproxy` needed no
  `UpstreamTLS` option.
- **Certificates** for TERMINATE sites are held in `certs.Set` (exact name,
  then wildcard, never another domain's). They're loaded from FileStore
  when a domain's fingerprint changes and cached on `/data` with mode 0600.
- **`common.LiveView`** is the shared cached reader of the live tables, with
  a TTL plus a refetch on a miss at most once a second. It replaces the
  relay link's own copy of the same logic.
- **KIND:** the edge runs on the node's host network. Host ports map to it:
  18443 → 443, 18080 → 80, 12222 → 2222, 16000 → 6000 (site tests), and
  22000–22009 → the same ports.

### 16.13 K4 decisions and findings (2026-09-26)

- **The evaluator polls.** Layer 8 has no change subscription for services
  another process owns (§16.2), and the `*_OFFLINE` conditions are about
  time anyway. The backend reads the rules, the live tables and the edge
  tables every 30 s, after a minute's grace at startup.
  - A table that can't be read skips the conditions that need it; nothing
    fires on missing data.
  - Edges that haven't reported for 2 minutes aren't judged, and simulated
    records never fire.
  - A watched token or agent with no record at all (records expire; a
    restarted registry knows only connected agents) counts as offline from
    the first evaluation that saw none.
- **Firing:** each target gets `Notify().Send` (the delivery log keeps every
  attempt, failed ones included), an `alert.fired` event is posted, and
  `last_fired` is PATCHed, which starts the cooldown. A rule that keeps
  holding fires again once per cooldown.
- **The logic is a pure evaluator** (`alerts/evaluate.go`), tested in
  process. The KIND test checks deliveries in the notify log and that the
  cooldown holds.
- **PUT for whole records, PATCH for partial updates.** The first KIND run
  fired a listener alert for a listener that was gone. The edge's PATCHed
  report kept the old fields: a PATCH skips zero values and never shrinks a
  list. Live-table rows and edge reports are the whole record, so they're
  now replaced with PUT. PATCH stays for partial updates such as
  `last_fired`.
- **Two l8reflect fixes, each reproduced by a test first:**
  - growing a primitive slice built a slice of pointers and panicked
    (`445d183`)
  - applying a change to one slice element left the element empty, so a
    PATCH that added list elements stored blanks (`647e2d1`)

### 16.14 K6 decisions and findings (2026-09-26)

- **Logs work in every mode.** Every process writes its logs under the
  security config's log directory, `/data/logs/l8tunnel` (the relay and
  edge send their data-plane logs to stdout, so they land in `.log`, not
  `.err`). Each pod also mounts that directory from a hostPath shared on
  its node, where the node's `log-agent` collects it. l8erp's per-pod
  volumes leave its agent only its own files.
- **One description, four manifests.** The four modes are generated from
  one description of the workloads, so their images, env, ports and volumes
  can't drift; only the workload kinds, storage and placement differ.
  Every mode validates against the Kubernetes API (server dry-run); only
  KIND runs here.
- **Added to every mode:** the relays' headless Service (the StatefulSet
  named a governing Service that didn't exist) and a NetworkPolicy that
  keeps the relays' ports inside the cluster; `NET_BIND_SERVICE` for the
  edge. `deploy.sh` waits for each app whatever its kind in the mode.
- **A relay's accounts snapshot is named per pod**, since local mode's two
  relays share `/data`.
- **Mock data** goes through the real services: `TunIssue` for tokens and
  certificates, FileStore for the sites' certificates, and one `TunClaim`
  announce per simulated relay for its agents and tunnels (the registry
  keeps them in memory, so they're gone after it restarts). The backend
  refuses an expired certificate, so the data has one expiring soon but no
  expired one. Demo operator and viewer users come through the Security
  API.
- **The import tool** wraps `TunIssue IMPORT` (tested in KIND); the agent CA
  from the same export goes in with `secrets.sh`.
- **Waived:** `run-local.sh` and the demo agent (X-6).
- **Deferred:** the `l8tunnel-oidc` Secret and the optional first-start
  `l8tunnel-tls` Secret (§7.2). The tunnel certificate is uploaded in the UI,
  and OIDC login for tunnels isn't wired in cluster mode yet; a tunnel that
  uses OIDC can't move to the cluster until it is.

### 16.15 K7 findings (2026-09-26)

- **Compliance walk:** no generics, no l8secure import, tests only in
  `go/tests`, gofmt clean, no PEM files, `dist/` or `vendor/` tracked, every
  enum has UNSPECIFIED, service names up to 10 characters, one owner per
  main. `base-core.css` was split (`base-noc.css`) to stay under the size
  limit.
- **Old agents:** the 5b19bbc agent binary works through the cluster
  (mode A through the edge, HTTP, its version on the agent record).
- **TERMINATE balanced per connection, not per request.** The edge kept one
  HTTP connection pool per forward, so a keep-alive client stuck to one
  backend (40 requests, all to one member). `httpproxy` now asks a
  `Balancer` for a backend per request and pools connections per backend,
  as §3.4 says; relay tunnels are unchanged. SOURCE_HASH on TERMINATE now
  sees the client address (it got an empty one before).
- **A UI read of tokens broke them.** The `tuntoken.secrethash` deny rule
  (on admin, the only role in use) blanked the hash in the backend's cache:
  l8utils' query cache passes its cached objects to `ScopeItem`, which
  blanks denied fields in place. After anyone listed tokens, relays read an
  empty hash and refused those agents. The rule was removed from the
  security config: the hash of a 32-byte random secret gives nothing away,
  and the UI never shows it. The framework behavior is noted for its owner
  (ReportInfraBugs); `TestKindTokenSurvivesUIRead` guards it.
- **New coverage:** per-request balancing and connection reuse, WebSocket
  and upstream certificate verification through the edge, weights within
  5% over 1,000 connections, agent token vs management bearer, relay pod
  loss (the agent comes back through the edge with the same port), the
  agent record (OS, arch, IP through the edge, RTT, heartbeat, a clean stop
  parking every tunnel), traffic and the agent's session through a registry
  restart, and an agent connecting with an imported token.
- **Not tested:** operator and viewer behavior. Every user is admin in this
  deployment.
