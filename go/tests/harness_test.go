package tests

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/oidc"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const (
	// Well-formed agent tokens (l8t_<id>_<secret>) stored by the harness.
	testToken  = "l8t_7e570001_testtesttesttesttesttesttesttesttesttesttes"
	otherToken = "l8t_07e40002_otherotherotherotherotherotherotherotheroth"
	baseDomain = "tunnel.test"
	controlSNI = "connect.tunnel.test"
)

// testLogger discards logs unless L8TUNNEL_TEST_LOG is set.
func testLogger() *slog.Logger {
	if os.Getenv("L8TUNNEL_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// relayOpts configures startRelayWith. Zero values pick fresh ports, a
// new PKI and the relay's default timings.
type relayOpts struct {
	ports            int // size of the TCP port range when portMin is 0
	portMin, portMax int
	controlAddr      string
	pki              *testPKI
	heartbeat        time.Duration
	grace            time.Duration
	httpListener     bool              // also listen for plain HTTP on 127.0.0.1
	noForwarded      bool              // disable X-Forwarded-* headers
	testPolicy       auth.Policy       // policy of the "test" token
	rateLimits       *relay.RateLimits // nil: limits high enough not to matter
	accessLog        bool
	logger           *slog.Logger  // nil: testLogger()
	login            *oidc.Service // OIDC login service, bound after start
	gateway          ssh.Signer    // enables the SSH gateway with this host key
	reserved         []string      // reserved tunnel names
	store            *store.Store  // reused across restarts
}

// relayEnv is a running relay on 127.0.0.1.
type relayEnv struct {
	srv   *relay.Server
	opts  relayOpts
	pki   *testPKI
	store *store.Store
	addr  string

	portMin, portMax int
}

// startRelay starts a relay whose TCP tunnel range has n free ports.
func startRelay(t testing.TB, n int) *relayEnv {
	t.Helper()
	return startRelayWith(t, relayOpts{ports: n})
}

func startRelayWith(t testing.TB, opts relayOpts) *relayEnv {
	t.Helper()
	if opts.pki == nil {
		opts.pki = newPKI(t)
	}
	if opts.portMin == 0 {
		opts.portMin, opts.portMax = freePortRange(t, opts.ports)
	}
	if opts.controlAddr == "" {
		opts.controlAddr = "127.0.0.1:0"
	}
	tlsCfg, err := transport.ServerTLSConfig(opts.pki.certFile, opts.pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if opts.store == nil {
		opts.store = newTestStore(t, opts.testPolicy)
	}
	limits := relay.RateLimits{ConnectionsPerSecond: 10000, ConnectionsBurst: 10000, AuthFailuresPerMinute: 10000}
	if opts.rateLimits != nil {
		limits = *opts.rateLimits
	}
	agentCA, err := opts.store.AgentCA()
	if err != nil {
		t.Fatal(err)
	}
	var reservations []relay.PermanentReservation
	stored, err := opts.store.Reservations()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range stored {
		reservations = append(reservations, relay.PermanentReservation{Name: r.Name, TokenID: r.TokenID, Port: r.Port})
	}
	logger := opts.logger
	if logger == nil {
		logger = testLogger()
	}
	httpAddr := ""
	if opts.httpListener {
		httpAddr = "127.0.0.1:0"
	}
	srv, err := relay.New(relay.Config{
		ControlAddr:             opts.controlAddr,
		HTTPAddr:                httpAddr,
		DisableForwardedHeaders: opts.noForwarded,
		TLS:                     tlsCfg,
		BaseDomain:              baseDomain,
		Tokens:                  opts.store,
		AgentCA:                 agentCA.Certificate(),
		Reservations:            reservations,
		RateLimits:              limits,
		AccessLog:               opts.accessLog,
		Login:                   loginService(opts.login),
		SSHGateway:              gatewayConfig(opts),
		ReservedNames:           opts.reserved,
		BindHost:                "127.0.0.1",
		TCPPortMin:              opts.portMin,
		TCPPortMax:              opts.portMax,
		HeartbeatInterval:       opts.heartbeat,
		NameGracePeriod:         opts.grace,
		Logger:                  logger,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	if opts.login != nil {
		opts.login.Bind(oidc.Binding{RuleFor: srv.OIDCRuleFor, HTTPSPort: srv.PublicHTTPSPort})
	}
	return &relayEnv{srv: srv, opts: opts, pki: opts.pki, store: opts.store, addr: srv.Addr().String(),
		portMin: opts.portMin, portMax: opts.portMax}
}

func gatewayConfig(opts relayOpts) *relay.GatewayConfig {
	if opts.gateway == nil {
		return nil
	}
	return &relay.GatewayConfig{Listen: "127.0.0.1:0", HostKey: opts.gateway, Keys: opts.store}
}

// loginService keeps a nil *oidc.Service a nil interface.
func loginService(s *oidc.Service) relay.LoginService {
	if s == nil {
		return nil
	}
	return s
}

// newTestStore opens a store holding the "test" and "other" tokens,
// hashed with bcrypt's minimum cost to keep the tests fast.
func newTestStore(t testing.TB, testPolicy auth.Policy) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "l8tunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	for name, tok := range map[string]string{"test": testToken, "other": otherToken} {
		policy := auth.Policy{}
		if name == "test" {
			policy = testPolicy
		}
		rec, err := auth.NewTokenRecord(name, tok, policy, bcrypt.MinCost)
		if err != nil {
			t.Fatal(err)
		}
		if err := st.AddToken(rec); err != nil {
			t.Fatal(err)
		}
	}
	return st
}

// restart closes the relay and starts a new one on the same control
// address, port range and certificate.
func (env *relayEnv) restart(t testing.TB) *relayEnv {
	t.Helper()
	if err := env.srv.Close(); err != nil {
		t.Fatal(err)
	}
	opts := env.opts
	opts.controlAddr = env.addr
	return startRelayWith(t, opts)
}

// freePortRange finds n consecutive ports on 127.0.0.1 that are free now.
func freePortRange(t testing.TB, n int) (int, int) {
	t.Helper()
	for attempt := 0; attempt < 100; attempt++ {
		base := 20000 + mrand.Intn(40000)
		free := true
		for p := base; p < base+n && free; p++ {
			ln, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				free = false
				continue
			}
			ln.Close()
		}
		if free {
			return base, base + n - 1
		}
	}
	t.Fatalf("no %d consecutive free ports found", n)
	return 0, 0
}

// runningAgent is an agent whose Run is executing in the background.
type runningAgent struct {
	agent  *agent.Agent
	cancel context.CancelFunc
	done   chan error
}

// newAgent builds an agent for env with the given token and tunnels.
func newAgent(t testing.TB, env *relayEnv, token string, tunnels ...agent.TunnelConfig) *agent.Agent {
	t.Helper()
	return newAgentWithID(t, env, token, "", tunnels...)
}

// newAgentWithID is newAgent with a fixed agent ID ("" generates one).
func newAgentWithID(t testing.TB, env *relayEnv, token, agentID string, tunnels ...agent.TunnelConfig) *agent.Agent {
	t.Helper()
	return newAgentWith(t, env, func(c *agent.Config) {
		c.Token, c.AgentID, c.Tunnels = token, agentID, tunnels
	})
}

// newAgentWith builds a test agent for env; edit adjusts the config.
func newAgentWith(t testing.TB, env *relayEnv, edit func(*agent.Config)) *agent.Agent {
	t.Helper()
	tlsCfg, err := transport.ClientTLSConfig(controlSNI, env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	cfg := agent.Config{
		RelayAddr:    env.addr,
		TLS:          tlsCfg,
		Token:        testToken,
		Version:      "test",
		Proxy:        transport.ProxyNone,
		ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 200 * time.Millisecond,
		Logger:       testLogger(),
	}
	edit(&cfg)
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// runAgent starts a in the background without waiting for it to be ready.
func runAgent(t testing.TB, a *agent.Agent) *runningAgent {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	ra := &runningAgent{agent: a, cancel: cancel, done: make(chan error, 1)}
	go func() { ra.done <- a.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		<-ra.done
	})
	return ra
}

// startAgent runs an agent and waits until its tunnels are registered.
func startAgent(t testing.TB, env *relayEnv, tunnels ...agent.TunnelConfig) *runningAgent {
	t.Helper()
	return waitReady(t, runAgent(t, newAgent(t, env, testToken, tunnels...)))
}

// waitReady waits until a running agent has registered its tunnels.
func waitReady(t testing.TB, ra *runningAgent) *runningAgent {
	t.Helper()
	select {
	case <-ra.agent.Ready():
	case err := <-ra.done:
		t.Fatalf("agent stopped before it was ready: %v", err)
	case <-time.After(10 * time.Second):
		t.Fatal("agent was not ready within 10s")
	}
	return ra
}

// runAgentExpectError runs an agent that must fail, and returns its error.
func runAgentExpectError(t testing.TB, env *relayEnv, token string, tunnels ...agent.TunnelConfig) error {
	t.Helper()
	ra := runAgent(t, newAgent(t, env, token, tunnels...))
	select {
	case err := <-ra.done:
		ra.done <- err // let the cleanup's receive complete
		return err
	case <-ra.agent.Ready():
		t.Fatal("agent registered, but it was expected to fail")
	case <-time.After(10 * time.Second):
		t.Fatal("agent neither failed nor registered within 10s")
	}
	return nil
}

// startEchoServer echoes every connection until EOF, then half-closes.
func startEchoServer(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
				conn.(*net.TCPConn).CloseWrite()
			}()
		}
	}()
	return ln.Addr().String()
}

// startBannerServer writes banner to every connection and closes it.
func startBannerServer(t testing.TB, banner string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			conn.Write([]byte(banner))
			conn.Close()
		}
	}()
	return ln.Addr().String()
}

// readBanner connects to addr and returns everything it sends.
func readBanner(addr string) (string, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	data, err := io.ReadAll(conn)
	return string(data), err
}

// stopAgent cancels a running agent and waits for Run to return.
func stopAgent(t testing.TB, ra *runningAgent) {
	t.Helper()
	ra.cancel()
	select {
	case err := <-ra.done:
		ra.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after cancel")
	}
}

// unusedAddr returns a 127.0.0.1 address nothing is listening on.
func unusedAddr(t testing.TB) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// publicAddr is the address tests dial for an endpoint's public port.
func publicAddr(port uint32) string {
	return fmt.Sprintf("127.0.0.1:%d", port)
}
