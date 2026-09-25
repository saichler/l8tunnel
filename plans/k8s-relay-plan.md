# l8tunnel on Kubernetes: clustered relay, edge proxy and management app

| | |
|---|---|
| **Status** | Draft, waiting for approval |
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
   tokens, reservations, gateway keys, agent certificates, edge routes and
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
   │    SNI / Host / port ─► route table ─► backend pool ─► PROXY v2    │
   └───────┬──────────────────────┬──────────────────────┬─────────────┘
           │ tunnel traffic:      │ agents (connect.*):  │ other domains
           │ to the owning relay  │ least-loaded relay   │ (EdgeRoute pools)
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
          │                │       │ sole owner of TunLive, TunRelay  │
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
  PATCH, DELETE) and service change notifications (`IServiceCacheListener`)
  over the vnet.
- Every in-memory service also has exactly one owner process. The live
  tables (`TunLive`, `TunRelay`) are owned by a dedicated single-replica
  **registry** process, not by the relays (§4.2).
- All users, roles and permissions go through `ISecurityProvider` (l8secure,
  loaded as a plugin). The relays and the edge join the vnet with
  service-account credentials from the security config JSON. The UI goes
  through l8web bearer-token auth. The project never imports l8secure.
- The relays' own access control for tunnel traffic (agent tokens,
  visitors' basic auth and OIDC, gateway keys) is **product functionality
  applied to third-party traffic**, not Layer 8 AAA. §5.7 defines its
  boundary. §15 lists it as explicit rule exceptions: agent ↔ relay auth
  (X-1) and tunnel-visitor and gateway auth (X-2), both approved by you.
- **The data plane keeps working when the management plane is down.**
  - Relays keep a local snapshot of tokens, reservations and gateway keys,
    and the edge keeps its routes (both are refreshed from change
    notifications).
  - Existing tunnels and new agent logins keep working.
  - Only management changes (for example issuing a token) wait until the
    management plane is back.

### 2.1 Components

| Component | Binary / image | Runs as | Role |
|---|---|---|---|
| Edge | `go/tun/edge` → `saichler/l8tunnel-edge` | hostNetwork, pinned to the router's target node | Public listeners, routing, load balancing, health checks, PROXY v2 to backends |
| Relay | `go/tun/relay` → `saichler/l8tunnel-relay` | 2+ replicas, pod network, no host ports | The existing relay in **cluster mode**: agent sessions, tunnel serving, HTTP termination, OIDC, SSH gateway |
| Registry | `go/tun/registry` → `saichler/l8tunnel-registry` | StatefulSet, 1 replica | The single owner of the in-memory live services `TunLive` and `TunRelay`: cluster-wide name, port and domain claims. No database |
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

A new package, `go/tunnel/edge`, plus the minimal `go/tun/edge/main.go`.

### 3.1 Listeners (on the host network)

| Public port | How the edge picks the route |
|---|---|
| 443 | Peeks the TLS ClientHello (SNI and ALPN) without terminating TLS, using the ClientHello reader extracted from the relay in Phase K0 |
| 80 | Peeks the first HTTP request's `Host` header |
| 22000–22999 (the relay's `tcp_port_range`) | Destination port: the mode A tunnel that holds that port |
| 2222 (when the SSH gateway is on) | Fixed route to the relay pool |

All of these come from configuration. A listener that can't bind fails at
startup (fail-fast).

### 3.2 Route resolution (443 and 80)

The edge checks the following in order; the first match wins:

1. **An EdgeRoute's exact domain** (for example `admin.layer8-tunnel.info`, or
   another site the operator hosts behind the same router).
2. **The control name** `connect.<base>`: goes to the relay pool, picking the
   ready relay with the fewest agent sessions (this balances agents across
   relays).
3. **A live tunnel's hostname**: `<name>.<base>`, or a custom domain from the
   live-tunnel table (§4.2). It goes to the relay that owns the tunnel. This
   route is affinity, not load balancing, because only that relay holds the
   agent's session.
4. **A wildcard EdgeRoute** (`*.example.com`).
5. **Anything else under `<base>`, with no SNI, or unknown**: the default
   route, which is the relay pool (round robin). This keeps today's behavior:
   the relay answers with its 404 page or TLS alert.

If the live-tunnel table is unavailable or stale, step 3 falls back to any
ready relay. That relay forwards the connection to the owner (§4.4), so a
stale table costs one extra hop and never fails a connection.

### 3.3 Route modes

| Mode | What the edge does | Used for |
|---|---|---|
| `RELAY` | L4: writes a PROXY v2 header, then passes the raw bytes through | Everything handled by relays |
| `PASSTHROUGH` | L4 to the route's backend pool. The PROXY v2 header is optional per route, because not every backend understands it | Sites that serve their own valid certificate |
| `TERMINATE` | Terminates TLS with the route's certificate (a mounted Secret), then reverse-proxies HTTP/1.1, h2 and WebSocket to the pool over https or http. Sets `X-Forwarded-For/Proto/Host` | Sites whose backends use self-signed certificates. This is what `l8web/go/web/proxy` does today; see §9 |

### 3.4 Load balancing and health

- **Pools.** A pool is made of static `address:port` members, a DNS name
  (every A record becomes a member, which works with headless Services and
  DaemonSets), or the relay pool (from `TunRelay` records, §4.3).
  Simulated records (§5.3) are never pool members or routes.
- **Algorithms.** Per route: `ROUND_ROBIN` (the default), `LEAST_CONN`,
  `SOURCE_HASH` (client-IP affinity), or weights.
- **Active health checks.** TCP connect, or an HTTP(S) GET on a path, every
  `interval` seconds. A member is marked down after N failures and back up
  after M successes. Relays are also marked down when their `TunRelay`
  heartbeat is older than 3 intervals, or when they report `DRAINING` (then
  they get no new agents).
- **Passive checks.** A failed dial marks the member suspect, and the edge
  retries the next member. It only retries before any client byte has been
  forwarded, so this is safe for TLS.
- **No healthy member.** A TLS route gets a TLS alert, an HTTP route gets a
  503 page. The edge also posts an event and the alert rules can notify
  (§5.5).

### 3.5 Client address and trust

- The edge adds a **PROXY protocol v2** header to every connection it forwards
  to relays (and to PASSTHROUGH backends when the route enables it).
  - Relays read it on their internal listeners, so IP allow and deny lists,
    rate limits, access logs and `X-Forwarded-For` keep seeing the real
    client IP.
  - Relays accept the header only from `cluster.trusted_proxies` (CIDRs).
    A NetworkPolicy lets only edge and relay pods reach the relay's internal
    ports.
- **Per-IP connection rate limiting** moves to the edge: one edge means a
  cluster-wide limit. Relays keep their per-IP auth-failure limits locally,
  so with N relays those limits are N times looser. This is documented.
- **An optional allow/deny IP list per EdgeRoute**, for example to keep the
  management UI LAN-only.

### 3.6 Configuration and caching

- The routes are `EdgeRoute` objects, edited in the management UI.
- The edge loads them over vnic at startup, applies change notifications, and
  writes the last good set to `/data/edge-routes.json`. It reads that file
  when the management plane is unreachable.
- A bootstrap file (ConfigMap) holds listeners, the base domain, the relay
  pool and trusted settings. When no routes are stored, the edge works with
  only the relay pool.
- Every few seconds the edge reports its status and backend health as an
  `EdgeNode` record, and it serves `/healthz`, `/readyz` and Prometheus
  `/metrics`: connections, bytes and dial failures per route and member.

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
| OIDC signing key, TLS certificate, OIDC client secrets | bbolt / files | Secrets shared by all relays, so cookies and codes validate on any relay |
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
    They use vnic RPC and change notifications only.
  - The registry has no database and doesn't depend on the management
    backend or Postgres. New agent registrations keep working while the
    management plane is down.
- **Registry restart.** The state is rebuilt, not persisted.
  - On startup the registry multicasts a re-announce request, and every relay
    re-POSTs its active and grace records. The registry's `/readyz` stays
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
├── edge/routes/          EdgeRouteService.go, ...Callback.go
├── edge/nodes/           EdgeNodeService.go (in-memory, TTL)
├── live/tunnels/         TunLiveService.go, ...Callback.go (in-memory, activated only by the registry)
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
| edge (41) | `EdgeRoute` | `EdgeRoute` | `routeId` | ORM | backend |
| edge (41) | `EdgeNode` | `EdgeNode` | `edgeId` | in-memory, TTL | backend |
| live (42) | `TunLive` | `TunLiveTunnel` | `tunnelId` | in-memory | registry (§4.2) |
| live (42) | `TunRelay` | `TunRelay` | `relayId` | in-memory | registry |
| alerts (43) | `TunAlert` | `TunAlertRule` | `ruleId` | ORM | backend |

**Children** (embedded as `repeated` fields, with no service, UI nav or
generator of their own):

- `TunTokenPolicy` and `TunPortRange` in `TunToken`
- `TunGatewayGrant` in `TunGatewayKey`
- `EdgeBackend` and `EdgeHealthCheck` in `EdgeRoute`
- `EdgeBackendStatus` in `EdgeNode`

**References between Prime Objects** are ID strings only, for example
`TunLiveTunnel.tokenId`, `TunLiveTunnel.relayId`, `TunAgentCert.tokenId` and
`TunReservation.tokenId`.

**`TunAlertRule.targets`** embeds the shared `l8notify.NotifyTarget` type.

**Protobuf rules:**

- Every enum starts with `*_UNSPECIFIED = 0`. The enums: `TunTunnelType`,
  `EdgeRouteMode`, `EdgeLbAlgorithm`, `EdgeHealthType`, `TunRelayState`,
  `TunLiveState`, `TunAlertCondition` and `TunIssueKind`.
- Every `XxxList` type has `repeated Xxx list = 1; l8api.L8MetaData metadata = 2;`.
- Bindings are generated only through `proto/make-bindings.sh` (`docker run -i`).

### 5.3 Service callbacks (key behavior)

**`TunToken`**

- `Before(POST)` generates `tokenId` (`common.GenerateID`) and validates the
  name and policy with the shared `auth` validators.
- `secretHash` is written only by `TunIssue`, or by import. The security
  config blanks it for UI roles (field-level deny rule
  `tuntoken.secrethash`), and only the relay service role can read it.
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
- **`EdgeRoute`:**
  - Validation:
    - domains must be unique across routes
    - a route under `<base>` blocks tunnels from using that name (`TunLive`
      checks EdgeRoute domains the way it checks reserved names)
    - TERMINATE needs a certificate reference
    - health-check bounds are checked
  - Every accepted change bumps a `routesVersion` that the edges report back.
- **`TunLive`, `TunRelay`, `EdgeNode` and simulated records:**
  - Each type has a `simulated` boolean. Only the `mock` service account
    may set it (the security config enforces this).
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
- edge backend down or up, and route set applied (edge)
- certificate expiring (backend)

The project never activates `Events` itself (l8common does), and the UI
`main.go` registers `EventRecord`.

### 5.5 Notifications (l8notify, NotifyServiceRequired)

- `TunAlertRule` conditions:
  - `RELAY_LOST`
  - `NO_READY_RELAY`
  - `EDGE_POOL_DOWN`
  - `CERT_EXPIRING` (threshold in days; relays report the TLS certificate's
    `NotAfter`, today Dec 24, 2026)
  - `TOKEN_OFFLINE` (all of a token's agents gone for longer than N minutes)
- The backend's `alerts/evaluator.go` subscribes to `TunRelay`, `EdgeNode`
  and `TunLive`. When a condition matches it sends through
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
  - `operator`: live views, drain, disconnect, reservations, routes; cannot
    issue tokens or certificates
  - `viewer`: read-only
  - `relay` (service account): read `TunToken` including `secretHash`; read
    reservations, gateway keys, certificates and routes; write `TunLive` and
    `TunRelay`
  - `edge` (service account): read routes, `TunLive` and `TunRelay`; write
    `EdgeNode`
  - `registry` (service account): read reservations and routes, for claim
    checks
  - `mock` (service account, only in `run-local.sh` and KIND): write
    simulated live records and seed configuration objects
- **Deny rules** blank `secretHash` for everyone except `relay`.
- **Provisioning** of users and roles goes only through the config JSON or
  the Security API (area 73), including from the mock data. There's no
  project-owned users service, and the project never imports l8secure.
- **Management UI exposure:** served through the edge as
  `admin.<base>` (PASSTHROUGH to `l8tunnel-web`, which serves the wildcard
  certificate). Its EdgeRoute has a LAN-only `allow_ips` by default, and
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
  - route edits
- Only the §5.6 roles apply. Users are provisioned only through the security
  config JSON or the Security API (area 73).
- Every management action is recorded as an event.
- The relays, the edge and the registry are ordinary vnic clients with
  service-account credentials. They get no privileges outside their roles.

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
| Dashboard | TunRelay, TunLive, EdgeNode | Layer8DWidget KPIs: ready relays, agents online, tunnels by type, unhealthy backends, days to certificate expiry | Mobile widgets | KPI counts query `page 0` (L8QL gotcha) |
| Tunnels ▸ Live | `TunLiveTunnel` | Layer8DTable `realtime`, read-only view form, **Disconnect** action | Layer8MTable, read-only card | Immutable, so read-only UI (ImmutabilityUiAlignment) |
| Tunnels ▸ Relays | `TunRelay` | Table (realtime), **Drain / Resume** actions | Same | Read-only apart from the state action |
| Tunnels ▸ Edge nodes | `EdgeNode` | Table; backend status as a read-only inline table | Same | |
| Access ▸ Tokens | `TunToken` | CRUD; the policy as form sections with an inline table for port ranges; **Issue token** runs a custom handler that POSTs to `TunIssue` and shows the token once, with copy | Same (mobile form and confirm) | `secretHash` never shown |
| Access ▸ Reservations | `TunReservation` | CRUD, token reference picker | Same | |
| Access ▸ Gateway keys | `TunGatewayKey` | CRUD, grants as an inline table | Same | |
| Access ▸ Agent certificates | `TunAgentCert` | List + **Issue certificate** (shown once, downloaded as PEM) + revoke (PATCH) | Same | |
| Edge ▸ Routes | `EdgeRoute` | CRUD; backends and health check as inline tables and sections; mode, LB and health-type enums | Same | |
| Alerts ▸ Rules | `TunAlertRule` | CRUD; targets use `l8notify-target-editor.js` | Same | |
| System | built-in | l8ui SYS: health, security (users and roles), modules, logs (L8Logs), data import; Events (`l8ui/events/`); Notify integrations and delivery log (`l8ui/notify/`) | Mobile SYS equivalents | |

- **Registration:** reference registry entries for every Prime Object (the
  token, route and relay pickers), and types registered in `go/tun/ui/main.go`.
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
| `saichler/l8tunnel-web` | `go/tun/ui` | `l8tunnel-security` | DaemonSet (hostNetwork) | StatefulSet + anti-affinity | DaemonSet |
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
    - Secrets are referenced but never committed: `l8tunnel-tls`,
      `l8tunnel-agent-ca`, `l8tunnel-cluster`, `l8tunnel-oidc`.
    - `k8s/secrets.sh` creates them from files.
  - a NetworkPolicy for the relay's internal ports
  - a headless Service for the relays
- **Storage by mode:** local uses hostPath `DirectoryOrCreate`; bare-metal
  uses `rancher.io/local-path` (Delete); GKE uses `kubernetes.io/gce-pd` with
  the shared `l8tunnel-data` PVC (Retain); KIND uses `standard`.
- **Your cluster:** `k8s/label-edge.sh <node>` labels k8s-node-2, because the
  router forwards to its static IP 192.168.1.120.

### 7.3 Local development (RunLocalScript)

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
| 4 | `EdgeRoute` | `gen_edge_routes.go`: routes in every mode and LB algorithm, pointing at `demo-*.invalid` backends | — |
| 5 | `TunAlert` | `gen_alerts.go`: one rule per condition, with email and webhook targets | `TunTokenIDs` |
| 6 | `TunRelay`, `EdgeNode` | `gen_live_relays.go`: 3 simulated relays and 1 simulated edge node (`simulated: true`, §5.3) | — |
| 7 | `TunLive` | `gen_live_tunnels.go`: 40 simulated tunnels across the simulated relays and tokens, in every type and state (ACTIVE, GRACE) | phases 1 and 6 |

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
2. `k8s/secrets.sh` loads the TLS certificate, the agent CA and newly
   generated cluster and OIDC keys.
3. Deploy, then import through `TunIssue IMPORT` (the UI's data-import page
   or `go/tun/tools/import`).
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
| 5 | `l8web/go/web/proxy`: an SNI-based TLS-terminating reverse proxy with hardcoded routes and `InsecureSkipVerify` to https backends | The edge TERMINATE mode covers the same job | Not reused: it lacks L4 passthrough, PROXY v2, dynamic routes, pools and health checks, and it lives in a framework repo (FrameworkInterfaceBoundaries). The edge replaces it on k8s-node-2 for any site moved into EdgeRoutes; l8web itself isn't changed. Flagged to the framework owner as a candidate to retire later |
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
- Record the outcomes in this plan before K1.

**K1 — Model and management backend**

- `proto/tun.proto` and bindings.
- `go/tun/common`; the ORM services and callbacks (access, edge routes,
  alerts); `TunIssue`; `EdgeNode`; the `simulated` flag and its rules.
- The security config JSON in l8secure, including the `relay`, `edge`,
  `registry` and `mock` service accounts; `go/tun/main` and `go/tun/vnet`.
- Registering events and notify types.

**K2 — Relay cluster mode**

- `tunnel/cluster`: `Accounts` over vnic with a snapshot, and `Registry` over
  `TunLive`.
- The registry process (`go/tun/registry`) as the single owner of
  `TunLive`/`TunRelay`; heartbeats, lost-relay cleanup, and re-announce
  after a registry restart.
- Internal listeners 8443, 8080 and 8444 with PROXY v2 and TLVs; relay-to-relay
  forwarding with HMAC.
- Cross-relay takeover and grace; drain; cluster config and fail-fast checks
  (admin socket off, no ACME).
- Relay events; the `export` command; `go/tun/relay/main.go`.

**K3 — Edge**

- `tunnel/edge`: listeners, route resolution (§3.2), modes RELAY,
  PASSTHROUGH and TERMINATE.
- Pools, LB algorithms, active and passive health, and retry before the
  first byte.
- PROXY v2 writer, per-IP rate limits and route IP lists.
- Route cache file, `EdgeNode` reporting, metrics and events;
  `go/tun/edge/main.go`.

**K4 — Alerts and notifications**

- The evaluator, the conditions in §5.5, cooldowns, and the certificate
  expiry reported by relays.

**K5 — Management UI**

- The desktop and mobile sections in §6, dashboard, realtime tables, the
  show-once handlers, Drain / Disconnect actions, and the SYS, Events and
  Notify sections.
- `login.json`, the reference registry, and verifying the script order.

**K6 — Deployment, local run, mock data**

- Every Dockerfile and `build.sh`, base images, `build-all-images.sh`, the
  four k8s modes, the KIND scripts, `deploy.sh`/`undeploy.sh`, `secrets.sh`,
  `label-edge.sh`.
- `log-vnet` and `log-agent`, `run-local.sh`, and the `go/tests/mocks`
  generators for all 10 services in 7 phases (§7.4), including simulated
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
  - management-plane-down resilience
  - registry restart: re-announce, no dropped tunnels, and claims resuming
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
| 10 | §5.3 | EdgeRoute and EdgeNode services; `simulated` flag rules | Go-mgmt | K1 |
| 11 | §5.6 | Security config JSON, roles, deny rules, service accounts | Go-mgmt | K1 |
| 12 | §5.4 | Events types registered; backend events | Go-mgmt | K1 |
| 13 | §4.1 | Accounts over vnic with a snapshot; revocation propagation | Go-relay | K2 |
| 14 | §4.2 | Registry as single owner of TunLive/TunRelay: claims, port allocation, takeover, grace, lost relay, re-announce | Go-relay | K2 |
| 15 | §4.3 | Internal listeners 8443/8080/8444 | Go-relay | K2 |
| 16 | §4.4 | Relay-to-relay forwarding with TLV + HMAC, no second hop | Go-relay | K2 |
| 17 | §4.5 | Drain (UI and preStop), paced session close | Go-relay | K2 |
| 18 | §4.6 | OIDC/custom-domain/admin-socket rules in cluster mode; fail-fast | Go-relay | K2 |
| 19 | §7.5 | `l8tunnel-server export` | Standalone | K2 |
| 20 | §3.1 | Edge listeners 443/80/port range/gateway | Go-edge | K3 |
| 21 | §3.2 | Route resolution order, stale-table fallback | Go-edge | K3 |
| 22 | §3.3 | RELAY, PASSTHROUGH, TERMINATE modes | Go-edge | K3 |
| 23 | §3.4 | Pools, LB algorithms, active and passive health, retry | Go-edge | K3 |
| 24 | §3.5 | PROXY v2 writer, edge rate limits, route IP lists | Go-edge | K3 |
| 25 | §3.6 | Route cache, bootstrap config, EdgeNode reporting, metrics | Go-edge | K3 |
| 26 | §5.5 | Alert rules, evaluator, Notify().Send, cooldown | Go-mgmt | K4 |
| 27 | §6 | Dashboard | Desktop | K5 |
| 28 | §6 | Dashboard | Mobile | K5 |
| 29 | §6 | Tunnels (Live, Relays, Edge nodes) with actions | Desktop | K5 |
| 30 | §6 | Tunnels (Live, Relays, Edge nodes) with actions | Mobile | K5 |
| 31 | §6 | Access (Tokens + issue, Reservations, Gateway keys, Agent certs + issue) | Desktop | K5 |
| 32 | §6 | Access (Tokens + issue, Reservations, Gateway keys, Agent certs + issue) | Mobile | K5 |
| 33 | §6 | Edge ▸ Routes | Desktop | K5 |
| 34 | §6 | Edge ▸ Routes | Mobile | K5 |
| 35 | §6 | Alerts ▸ Rules | Desktop | K5 |
| 36 | §6 | Alerts ▸ Rules | Mobile | K5 |
| 37 | §6 | System, Events, Notify sections; login.json; reference registry | Desktop | K5 |
| 38 | §6 | System, Events, Notify sections; login.json; reference registry | Mobile | K5 |
| 39 | §7.1 | Dockerfiles, build.sh, base images, build-all-images.sh | K8s | K6 |
| 40 | §7.2 | Four k8s modes, KIND scripts, deploy/undeploy, secrets.sh, label-edge.sh | K8s | K6 |
| 41 | §7.1 | log-vnet and log-agent binaries, images, YAML entries | K8s | K6 |
| 42 | §7.3 | run-local.sh, PRD "Local Development Setup" | Go-mgmt | K6 |
| 43 | §7.4 | Mock generators for all 10 services (7 phases, simulated live records) + demo agent | Go-mgmt | K6 |
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
| Moving the other Layer 8 sites (probler.dev, l8erp.one, ...) off `l8web` proxy | Not needed for l8tunnel; each move is an EdgeRoute entry | Add EdgeRoutes (TERMINATE, backends as today) once the edge is live |

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
| ImmutabilityUiAlignment | `TunLiveTunnel`, `TunRelay`, `EdgeNode` read-only in the UI (actions only) | K5 |
| Layer8DTablePaginationMetadata / L8QueryRules | Counts on `page 0`; every GET with L8Query; `select *` for detail popups | K5 |
| SpecialCases (read-only services, custom handlers) | Live services read-only; Issue as custom handlers | K5 |
| ProtobufRules | UNSPECIFIED zero values, `list=1`/`metadata=2`, type names in JS, `make-bindings.sh` with `-i` | K1 grep |
| PrimeObjectReferences | Children embedded; references by ID only (§5.2) | K1 review |
| Maintainability (≤500 lines, split at 450; ServiceName ≤10; area per module; GenerateID in Before POST; UI type registration; duplication) | §5.2 names are 7–9 characters; callbacks generate IDs; K0 extractions | K7 greps |
| MainPackageMinimal | Each `main.go` only wires resources, vnic, Activate and waits | K7 review |
| NoGoGenerics | None | K7 grep |
| FrameworkInterfaceBoundaries | No changes to `l8types/go/ifs`; existing extension points (ServiceCallback, IServiceCacheListener) | K7 review |
| SingleOwnerDatabaseTable | Every service has exactly one owner process (§5.2): ORM services in the backend; `TunLive`/`TunRelay` in the registry; `EdgeNode` in the backend. Relays, edge and UI only use vnic | K7 grep for `Activate` per `main.go` |
| SecurityRules / SecurityConfigStructure / AssociateIdsScopeView | Management plane: ISecurityProvider only; config JSON in l8secure; users via area 73; no l8secure import; field deny for `secretHash`. Data plane: §5.7 boundary, exceptions X-1 and X-2, both approved (§15) | K1, K7 grep and separation tests |
| EventsServiceRequired | Never activated by the project; `EventRecord` registered; events §5.4 | K1, K7 grep |
| NotifyServiceRequired | `Notify().Send` only; types registered; no `net/smtp` or Slack code | K4, K7 grep |
| LogServicesRequired / L8Logs | log-vnet and log-agent in every artifact list; LOGPATH `/data/logs/l8tunnel`; the SYS log viewer | K6 |
| DeploymentArtifacts | §7.1; every new image on the own `-security`/`-postgres` base images; standalone images are exception X-5 | K6 |
| K8sRules | §7.2; the rule's verify greps | K6 |
| RunLocalScript | §7.3 | K6 |
| MockDataRules | §7.4: generators for all 10 services in 7 dependency-ordered phases (live services through simulated records), endpoints `/tun/<area>/<ServiceName>`, users through area 73 | K6 |
| TestLocationAndApproach / CleanupTestBinaries | Tests only in `go/tests/`, through system APIs; built test binaries removed | K7 |
| PostImplementationE2ETesting | `e2e/` Playwright on KIND, desktop and mobile, hygiene rules | K8 |
| VerifyPrdCompletenessBeforeDone | Section-by-section walk in the K8 report | K8 |
| LoginJsonAdaptation / SetupConfiguration / ModconfigFailureNoLogout | `login.json` adapted (§6); ModConfig failures don't log out | K5 |
| PortalsSameWebServer | One UI server, one portal | K6 |
| VendorAndGit | Dependencies only through `vendor.sh`; `go/vendor/` untracked; git only when asked | every phase |
| NeverActOnQuestions | Followed | — |
| Not applicable | L8Pollaris*, DataCompletenessPipeline, MoneyFieldTypeMapping, DateField pipeline beyond timestamps, FileUploadPattern, RegistrationPage (admins provision users), LoginableEntityUserProvisioning, L8AgentChat, Layer8CsvExport (optional, not planned), DemoDirectorySync, PlatformConversionDataFlow (no platform conversion) | — |

**Also kept from the l8tunnel PRD §13.2:** no ignored errors, gofmt,
`dist/` and `.pem` files never committed, and Secrets never committed.

## 15. Rule exceptions

Every place this plan departs from a guideline, stated explicitly.
Everything not listed here complies.

| # | Rule | Exception | Scope | Why | Status |
|---|---|---|---|---|---|
| X-1 | SecurityRules (all AAA through `ISecurityProvider`) | Agent ↔ relay authentication (agent tokens and mTLS agent certificates) is done by the relay, not `ISecurityProvider` | `go/tunnel/auth`, the relay's control path | A wire-protocol credential for machines, checked on the hot path and needed while the management plane is down. Issuing and revoking these credentials stays under `ISecurityProvider` (§5.7) | **Approved by you** (2026-09-25) |
| X-2 | SecurityRules | Tunnel-visitor access control (IP lists, basic auth, OIDC login cookies, SSH access tokens) and SSH gateway keys are done by the relay | `go/tunnel/auth`, `oidc`, `httpproxy`, the relay gateway | Anonymous internet clients of the operator's customers, not Layer 8 users; the policies come from the tunnel owner's `Register` message. Bounded as in §5.7 | **Approved by you** (2026-09-25, covered by the X-1 waiver) |
| X-3 | SingleOwnerDatabaseTable, intent | None any more: `TunLive`/`TunRelay` now have one owner, the registry (§4.2) | — | Resolved by design | Resolved |
| X-4 | PrdCompliance (l8erp layout) | The existing `go/cmd/*` binaries and `go/tunnel/*` packages keep their layout; only new code follows `go/tun/…` | Existing standalone and data-plane code | They are the standalone product and the shared data-plane library, built by the release tarballs, the Dockerfile and the install packages; moving them would break those for no gain | **Approved by you** (2026-09-25) |
| X-5 | DeploymentArtifacts (own `-security`/`-postgres` base images) | The root `Dockerfile`'s standalone `server`/`agent` images stay distroless | Standalone images only | They never join a vnet or load a security plugin, and aren't part of any Kubernetes deployment in this plan. Every new image uses the base images | **Approved by you** (2026-09-25) |

All five are copied into the PRD in K6, so the exceptions stay visible
after this plan is done.
