# l8tunnel: P5 final verification

| | |
|---|---|
| **Date** | 2026-09-25 |
| **Branch** | `tunnel-mvp` |
| **Scope** | PRD §10.3, every requirement in the §10.2 traceability matrix |

## Summary

v1 (P0–P4) is implemented and verified, with three gaps that need hardware
or accounts this environment doesn't have (see [Not verified](#not-verified)):
`acme.mode: dns01` against a real DNS provider, running the agent on real
macOS and Windows machines, and benchmarks on a real 2-vCPU VM over a real
network.

- 77 end-to-end tests in `go/tests/` pass, repeatedly, with the race
  detector (`go test -race -count=N ./tests/...`).
- Real-binary smoke runs covered OpenSSH (`ssh`, `scp`) in both SSH modes,
  ACME HTTP-01 against Pebble, the admin workflow, Docker, and an agent
  behind an HTTP proxy.
- Performance targets are met by wide margins on the test machine.

## §10.3 checklist

| # | Step | Result | Evidence |
|---|---|---|---|
| 1 | SSH: mode A and mode B, interactive session, `scp` of a large file | ✅ | Real `sshd`, `ssh` and `scp` through the real binaries: `ssh -p` (mode A) and `ProxyCommand l8tunnel connect` (mode B); 5 MB `scp` byte-identical over both. Tests: `TestSSHTunnelConcurrentConnections`, `TestModeBConnectRoundTrip`, `TestTCPTunnelRoundTripLargePayload` (8 MB). Port forwarding over SSH was not exercised separately; it is ordinary SSH traffic on the same stream. |
| 2 | HTTPS: termination, passthrough, error pages, port 80 redirect | ✅ | `TestHTTPTunnelProxiesRequestsWithForwardedHeaders`, `TestHTTPTunnelServesHTTP2`, `TestHTTPTunnelWebSocketUpgrade`, `TestHTTPTunnelLargeUpload` (8 MB, HTTP/1.1 and HTTP/2), `TestHTTPTunnelStreamsResponsesWithoutBuffering`, `TestTLSPassthroughKeepsEndToEndEncryption` (client sees the backend's certificate), `TestHTTPErrorPages`, `TestPlainHTTPRedirectsToHTTPS`, `TestHTTPHostMustMatchSNI` |
| 3 | Resilience: relay restart, dropped network, same public name | ✅ | `TestAgentReconnectsAfterRelayRestart` (same name and port), `TestAgentReconnectsWhenRelayStopsAnswering`, `TestRelayDropsAgentThatMissesHeartbeats`, `TestReconnectedAgentTakesOverStaleSession`. Real binaries: agent back about 1.1 s after a relay restart. A real Wi-Fi↔LTE switch was not tested; the silent-relay test covers the same failure (a dead connection detected by heartbeats). |
| 4 | Security: revocation, basic auth, IP lists, SSH access tokens, fail-fast config, unreachable tunnel on bad auth policy | ✅ | `TestRevokedTokenDisconnectsAgentForGood`, `TestHTTPBasicAuth`, `TestIPAllowAndDenyLists`, `TestHTTPIPDenyGets403`, `TestAccessTokenProtectsModeB`, `TestAccessPolicyValidation`, `TestAuthFailureLimitBlocksAgents`, `TestConnectionRateLimit`, `TestTokenPolicy*`, `TestRelayConfigFailsFast`, `TestAgentConfigFailsFast`, `TestCertificateConfigFailsFast`, `TestUnsupportedProtocolVersionRejected`, `TestFailedRegistrationRollsBackAllTunnels` |
| 5 | Platforms: agent and client on Linux amd64/arm64, macOS, Windows | ⚠️ partial | Linux amd64: all tests and smoke runs. Cross-compiled with `build.sh` for linux/arm64, linux/armv7, darwin/amd64, darwin/arm64, windows/amd64, windows/arm64 (static binaries, correct formats). **Not run** on arm64, macOS or Windows hardware. |
| 6 | Performance: ≤5 ms added latency, ≥500 Mbps, ≥1,000 connections, ≥100 agents, idle agent <20 MB | ✅ (on this machine) | See [Performance](#performance). |
| 7 | Coding-rule compliance (§13.2) | ✅ | No generics; no file over 450 lines; tests only in `go/tests/`; every enum zero value `_UNSPECIFIED`; no ignored errors; gofmt clean; `go/vendor/` and `dist/` not tracked. |
| 8 | Completeness: every requirement in §10.2 implemented and tested | ✅ | See [Traceability](#traceability). The walk found one untested requirement (C-8, protocol version), now covered by `TestUnsupportedProtocolVersionRejected`. |

## Performance

Intel i5-8365U (4 cores, 8 threads), Linux. The relay, agent, clients and
test services run in one process over loopback, so these numbers measure
the relay's and agent's own cost, not network limits.

| Target (PRD §8) | Measured | Test |
|---|---|---|
| ≤5 ms added latency | median 52–55 µs added per 1-byte round trip (7–8 µs direct, 60–62 µs tunneled) | `BenchmarkAddedLatency` |
| ≥500 Mbps on 2 vCPU | 6.7 Gbit/s one connection, 7.0 Gbit/s over 8 connections with `-cpu 2` (6.9 / 7.4 Gbit/s unrestricted) | `BenchmarkThroughput1Conn`, `BenchmarkThroughput8Conns` |
| ≥1,000 concurrent connections | 1,000 open at once through one tunnel, each echoing | `TestScale1000ConcurrentConnections` |
| ≥100 agents | 100 agents registered and used on one relay | `TestScale100Agents` |
| Idle agent <20 MB RSS | 13 MB after 20 s idle (WebSocket transport, through a proxy) | Smoke run with the release binary |

`-cpu 2` limits Go's threads but not the kernel's loopback TCP work, so a
real 2-vCPU VM over a real network will measure lower. The margin (over
13× the target) leaves plenty of room.

Reproduce: `cd go && go test ./tests/ -run '^$' -bench . -benchtime 3x [-cpu 2]`.

## Traceability

| # | Requirements | Verified by |
|---|---|---|
| 1 | C-1, C-2, C-3, C-4, C-8 | Every agent test; `TestControlSNIServesOnlyAgents`, `TestInvalidTokenRejected`, `TestUnsupportedProtocolVersionRejected`, `TestFailedRegistrationRollsBackAllTunnels` |
| 2 | Backpressure | `TestSSHTunnelConcurrentConnections`, `TestScale1000ConcurrentConnections`, throughput benchmarks (8 concurrent streams on one session) |
| 3 | §13.1, §13.3 | Repo layout; `proto/make-bindings.sh`; enum check |
| 4 | C-5, C-6, Reliability | `TestHeartbeatsKeepIdleSessionAlive`, `TestRelayDropsAgentThatMissesHeartbeats`, `TestAgentReconnects*`, `TestNameHeldForTokenDuringGracePeriod`, `TestReconnectedAgentTakesOverStaleSession` |
| 5 | S-1, S-2, S-3, S-4, S-6 | `TestModeB*`, `TestMultipleTunnelsFixedAndAllocatedPorts`, `TestTunnelNameReservedForControlSNI`; real OpenSSH smoke runs |
| 6 | A-1, A-2, A-3, A-4 | `TestAgentYAMLConfig`, `TestAgentCommandLine`, `TestDeployExamplesParse`; `systemd-analyze verify` on both units |
| 7 | Fail-fast | `Test*FailsFast`, `TestAgentYAMLRejectsBadFiles`, `TestAccessPolicyValidation`, `TestTransportAndProxyConfig` |
| 8 | H-1, H-2, H-3, H-4, H-5, H-8, H-9 | `TestHTTP*`, `TestTLSPassthroughKeepsEndToEndEncryption`, `TestForwardedHeadersCanBeDisabled`, `TestPlainHTTPRedirectsToHTTPS`, `TestBrowserOnUnknownHostGetsErrorPageButRawClientsGetAlert` |
| 9 | V-1 | `TestCertificateConfigFailsFast` (11 misconfigurations); ACME HTTP-01 end to end against Pebble with the real binaries (startup certificate, on-demand certificate for a reserved name only, reload from storage without new orders) |
| 10 | H-7, S-5 | `TestHTTPBasicAuth`, `TestIPAllowAndDenyLists`, `TestHTTPIPDenyGets403`, `TestAccessTokenProtectsModeB` |
| 11 | V-2, V-3, V-4, V-5, V-6 | `TestAdminCLIManagesTokensAndReservations`, `TestTokenPolicy*`, `TestPermanentReservationSurvivesRestart`, `TestRelayStatusCountsConnectionsAndBytes`, `TestStorePersistsAndLocks`, `TestAdminSocketSafety` |
| 12 | A-5 | `TestAgentStatusSocket` |
| 13 | Security NFR | Rate-limit, auth-failure and token tests above; bcrypt-only token storage (`TestStorePersistsAndLocks`); `CAP_NET_BIND_SERVICE` in the systemd unit |
| 14 | C-7 | `TestWebSocketTransport`, `TestAgentThroughHTTPProxy` (both transports, proxy auth), `TestProxyRefusalIsReported`, `TestConnectThroughHTTPProxy`; smoke run: agent → CONNECT proxy → wss → relay in Docker |
| 15 | O-1, O-2, O-3 | `TestHTTPAccessLogAndConnectionLog`, `TestMetricsEndpoint`, `TestLogConfig` |
| 16 | Portability, Distribution, Resource use | `build.sh` for 7 targets; Docker server and agent images built and run (non-root, about 30 MB); idle RSS 13 MB |
| 17 | Performance, §11 metrics | Benchmarks and scale tests above |
| 18 | §13.2 | Compliance checks above |
| 19 | v1.1 (H-6, OIDC, O-4, SSH mode C, mTLS) | Deferred by plan |

## Not verified

1. **`acme.mode: dns01` against a real provider.** It needs a Cloudflare
   account and a domain. Its configuration handling is tested, and it goes
   through the same certmagic path as `http01`, which was verified against
   Pebble.
2. **Agent and client on real arm64, macOS and Windows machines.** The
   builds succeed; nothing platform-specific is used beyond Unix sockets
   (supported on Windows 10+) and signals.
3. **Benchmarks on a real 2-vCPU VM over a real network**, and a real
   network switch (Wi-Fi↔LTE) during a session.
4. **Let's Encrypt production.** Only Pebble (Let's Encrypt's test CA) was
   used.

## Defects found during verification (all fixed)

Found by tests or smoke runs across P0–P5, recorded here because unit tests
alone would not have caught most of them:

- TLS passthrough hung: the ClientHello replay wrapper inherited
  `WriteTo` from `*net.TCPConn`, so `io.Copy` skipped the replayed bytes.
- `acme.mode: http01` didn't obtain certificates at startup (certmagic
  defers when on-demand issuance is enabled), and startup challenges used
  `:80` instead of `listen.http`. Found only by the Pebble run.
- A wrong SSH access token looked like success to `l8tunnel connect`
  (exit 0, no output); the relay now acknowledges explicitly.
- Over-long admin socket paths failed with a bare `invalid argument`.
- The WebSocket client added a second TLS layer (`wss://` URL on an
  already-TLS connection).
- The Docker image's state directories were root-owned, so the non-root
  relay couldn't open its database.
