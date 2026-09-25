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

const testToken = "test-token-0123456789abcdef"

// testLogger discards logs unless L8TUNNEL_TEST_LOG is set.
func testLogger() *slog.Logger {
	if os.Getenv("L8TUNNEL_TEST_LOG") != "" {
		return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// testPKI is a throwaway CA and a relay certificate for localhost.
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
		Subject:      pkix.Name{CommonName: "localhost"},
		DNSNames:     []string{"localhost"},
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

// relayEnv is a running relay on 127.0.0.1.
type relayEnv struct {
	srv              *relay.Server
	pki              *testPKI
	addr             string
	portMin, portMax int
}

// startRelay starts a relay whose TCP tunnel range has n free ports.
func startRelay(t *testing.T, n int) *relayEnv {
	t.Helper()
	pki := newPKI(t)
	tlsCfg, err := transport.ServerTLSConfig(pki.certFile, pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tokensFile := filepath.Join(t.TempDir(), "tokens")
	if err := os.WriteFile(tokensFile, []byte("# test tokens\ntest "+testToken+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.LoadTokensFile(tokensFile)
	if err != nil {
		t.Fatal(err)
	}
	portMin, portMax := freePortRange(t, n)
	srv, err := relay.New(relay.Config{
		ControlAddr: "127.0.0.1:0",
		TLS:         tlsCfg,
		Tokens:      tokens,
		PublicHost:  "localhost",
		BindHost:    "127.0.0.1",
		TCPPortMin:  portMin,
		TCPPortMax:  portMax,
		Logger:      testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { srv.Close() })
	return &relayEnv{srv: srv, pki: pki, addr: srv.Addr().String(), portMin: portMin, portMax: portMax}
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
	tlsCfg, err := transport.ClientTLSConfig("localhost", env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{
		RelayAddr: env.addr,
		TLS:       tlsCfg,
		Token:     token,
		Version:   "test",
		Tunnels:   tunnels,
		Logger:    testLogger(),
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
	ra := runAgent(t, newAgent(t, env, testToken, tunnels...))
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
