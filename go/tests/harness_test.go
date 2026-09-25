package tests

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log/slog"
	"math/big"
	mrand "math/rand"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

const (
	testToken  = "test-token-0123456789abcdef"
	otherToken = "other-token-0123456789abcdef"
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

// testPKI is a throwaway CA and a relay certificate for *.tunnel.test.
type testPKI struct {
	caFile, certFile, keyFile string
}

func newPKI(t *testing.T) *testPKI {
	t.Helper()
	dir := t.TempDir()
	caKey := mustKey(t)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "l8tunnel test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey := mustKey(t)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: controlSNI},
		DNSNames:     []string{controlSNI, "*." + baseDomain},
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(leafKey)
	if err != nil {
		t.Fatal(err)
	}

	p := &testPKI{
		caFile:   filepath.Join(dir, "ca.pem"),
		certFile: filepath.Join(dir, "relay.pem"),
		keyFile:  filepath.Join(dir, "relay-key.pem"),
	}
	writePEM(t, p.caFile, "CERTIFICATE", caDER)
	writePEM(t, p.certFile, "CERTIFICATE", leafDER)
	writePEM(t, p.keyFile, "EC PRIVATE KEY", keyDER)
	return p
}

func mustKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func writePEM(t *testing.T, path, blockType string, der []byte) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
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
}

// relayEnv is a running relay on 127.0.0.1.
type relayEnv struct {
	srv  *relay.Server
	opts relayOpts
	pki  *testPKI
	addr string

	portMin, portMax int
}

// startRelay starts a relay whose TCP tunnel range has n free ports.
func startRelay(t *testing.T, n int) *relayEnv {
	t.Helper()
	return startRelayWith(t, relayOpts{ports: n})
}

func startRelayWith(t *testing.T, opts relayOpts) *relayEnv {
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
	tokensFile := filepath.Join(t.TempDir(), "tokens")
	lines := "# test tokens\ntest " + testToken + "\nother " + otherToken + "\n"
	if err := os.WriteFile(tokensFile, []byte(lines), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.LoadTokensFile(tokensFile)
	if err != nil {
		t.Fatal(err)
	}
	srv, err := relay.New(relay.Config{
		ControlAddr:       opts.controlAddr,
		TLS:               tlsCfg,
		BaseDomain:        baseDomain,
		Tokens:            tokens,
		BindHost:          "127.0.0.1",
		TCPPortMin:        opts.portMin,
		TCPPortMax:        opts.portMax,
		HeartbeatInterval: opts.heartbeat,
		NameGracePeriod:   opts.grace,
		Logger:            testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return &relayEnv{srv: srv, opts: opts, pki: opts.pki, addr: srv.Addr().String(),
		portMin: opts.portMin, portMax: opts.portMax}
}

// restart closes the relay and starts a new one on the same control
// address, port range and certificate.
func (env *relayEnv) restart(t *testing.T) *relayEnv {
	t.Helper()
	if err := env.srv.Close(); err != nil {
		t.Fatal(err)
	}
	opts := env.opts
	opts.controlAddr = env.addr
	return startRelayWith(t, opts)
}

// freePortRange finds n consecutive ports on 127.0.0.1 that are free now.
func freePortRange(t *testing.T, n int) (int, int) {
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
func newAgent(t *testing.T, env *relayEnv, token string, tunnels ...agent.TunnelConfig) *agent.Agent {
	t.Helper()
	return newAgentWithID(t, env, token, "", tunnels...)
}

// newAgentWithID is newAgent with a fixed agent ID ("" generates one).
func newAgentWithID(t *testing.T, env *relayEnv, token, agentID string, tunnels ...agent.TunnelConfig) *agent.Agent {
	t.Helper()
	tlsCfg, err := transport.ClientTLSConfig(controlSNI, env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{
		RelayAddr:    env.addr,
		TLS:          tlsCfg,
		Token:        token,
		AgentID:      agentID,
		Version:      "test",
		Tunnels:      tunnels,
		ReconnectMin: 50 * time.Millisecond,
		ReconnectMax: 200 * time.Millisecond,
		Logger:       testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return a
}

// runAgent starts a in the background without waiting for it to be ready.
func runAgent(t *testing.T, a *agent.Agent) *runningAgent {
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
func startAgent(t *testing.T, env *relayEnv, tunnels ...agent.TunnelConfig) *runningAgent {
	t.Helper()
	return waitReady(t, runAgent(t, newAgent(t, env, testToken, tunnels...)))
}

// waitReady waits until a running agent has registered its tunnels.
func waitReady(t *testing.T, ra *runningAgent) *runningAgent {
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
func runAgentExpectError(t *testing.T, env *relayEnv, token string, tunnels ...agent.TunnelConfig) error {
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
func startEchoServer(t *testing.T) string {
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
func startBannerServer(t *testing.T, banner string) string {
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
func stopAgent(t *testing.T, ra *runningAgent) {
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
func unusedAddr(t *testing.T) string {
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
