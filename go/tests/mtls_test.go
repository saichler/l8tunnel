package tests

import (
	"crypto/tls"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// issueCert issues an agent certificate for a stored token and returns a
// client TLS config carrying it.
func issueCert(t *testing.T, env *relayEnv, token string) *tls.Config {
	t.Helper()
	issued, _, err := env.store.IssueCert(token, 30)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "agent.crt"), filepath.Join(dir, "agent.key")
	os.WriteFile(certFile, issued.CertPEM, 0o644)
	os.WriteFile(keyFile, issued.KeyPEM, 0o600)
	cfg := mustClientTLS(t, env)
	if err := transport.LoadClientCert(cfg, certFile, keyFile); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func certAgent(t *testing.T, env *relayEnv, tlsCfg *tls.Config, token string, tr string) *runningAgent {
	t.Helper()
	return runAgent(t, newAgentWith(t, env, func(c *agent.Config) {
		c.TLS, c.Token, c.Transport = tlsCfg, token, tr
		c.Tunnels = []agent.TunnelConfig{{Type: tcpType, Target: startEchoServer(t)}}
	}))
}

func TestAgentAuthenticatesWithCertificateOnly(t *testing.T) {
	env := startRelay(t, 2)
	cfg := issueCert(t, env, "test")
	for _, tr := range []string{transport.TransportTLS, transport.TransportWebSocket} {
		ra := waitReady(t, certAgent(t, env, cfg, "", tr))
		if got, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), []byte(tr)); err != nil || string(got) != tr {
			t.Fatalf("%s: %q %v", tr, got, err)
		}
		stopAgent(t, ra)
	}
	if s := env.srv.Status(); len(s.Parked) == 0 {
		t.Fatal("expected the stopped agents' tunnels to be parked")
	}
}

func TestRevokedTokenRevokesItsCertificates(t *testing.T) {
	env := startRelay(t, 1)
	cfg := issueCert(t, env, "test")
	ra := waitReady(t, certAgent(t, env, cfg, "", transport.TransportTLS))
	rec, _ := env.store.TokenByName("test")
	env.store.DeleteToken(rec.ID)
	env.srv.DisconnectToken(rec.ID)
	select {
	case err := <-ra.done:
		ra.done <- err
		expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	case <-time.After(5 * time.Second):
		t.Fatal("agent with a revoked certificate kept running")
	}
}

func TestRequireCertPolicy(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 2, testPolicy: auth.Policy{RequireCert: true}})
	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	if !strings.Contains(err.Error(), "requires a client certificate") {
		t.Fatalf("error %v should say a certificate is required", err)
	}
	// Token plus its own certificate, and certificate alone, both work.
	cfg := issueCert(t, env, "test")
	waitReady(t, certAgent(t, env, cfg, testToken, transport.TransportTLS))
	waitReady(t, certAgent(t, env, cfg, "", transport.TransportTLS))
}

func TestCertificateAndTokenMustMatch(t *testing.T) {
	env := startRelay(t, 1)
	cfg := issueCert(t, env, "other")
	ra := certAgent(t, env, cfg, testToken, transport.TransportTLS)
	select {
	case err := <-ra.done:
		ra.done <- err
		expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	case <-ra.agent.Ready():
		t.Fatal("an agent with one token's certificate and another's token registered")
	case <-time.After(5 * time.Second):
		t.Fatal("no answer")
	}
}

func TestForeignCertificateRefused(t *testing.T) {
	env := startRelay(t, 1)
	// A certificate from a different relay's agent CA (the other env).
	other := startRelay(t, 1)
	cfg := issueCert(t, other, "test")
	cfg.RootCAs = mustClientTLS(t, env).RootCAs
	ra := certAgent(t, env, cfg, "", transport.TransportTLS)
	select {
	case <-ra.agent.Ready():
		t.Fatal("an agent with a foreign certificate registered")
	case <-time.After(time.Second):
	}
	// In TLS 1.3 the server checks the client certificate after the client
	// considers the handshake done, so the refusal arrives on first read.
	conn, err := transport.DialRelay(t.Context(), env.addr, cfg, transport.DialOptions{Proxy: transport.ProxyNone})
	if err == nil {
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		_, err = conn.Read(make([]byte, 1))
	}
	if err == nil || !(strings.Contains(err.Error(), "unknown certificate authority") || strings.Contains(err.Error(), "bad certificate")) {
		t.Fatalf("foreign client certificate: %v, want a certificate alert", err)
	}
}

func TestAgentCAPersists(t *testing.T) {
	env := startRelay(t, 1)
	a, err := env.store.AgentCA()
	if err != nil {
		t.Fatal(err)
	}
	b, err := env.store.AgentCA()
	if err != nil {
		t.Fatal(err)
	}
	if !a.Certificate().Equal(b.Certificate()) {
		t.Fatal("the agent CA changed between calls")
	}
	if _, _, err := env.store.IssueCert("nobody", 30); err == nil {
		t.Fatal("issued a certificate for an unknown token")
	}
	if _, _, err := env.store.IssueCert("test", 0); err == nil {
		t.Fatal("issued a certificate valid for 0 days")
	}
}

func TestAdminIssuesAgentCertificate(t *testing.T) {
	env := startRelay(t, 1)
	socket := startAdmin(t, env)
	mustAdmin(t, socket, "token", "create", "--name", "edge", "--require-cert")
	prefix := filepath.Join(t.TempDir(), "edge")
	out := mustAdmin(t, socket, "agent-cert", "issue", "--token", "edge", "--out", prefix, "--days", "90")
	if !strings.Contains(out, "issued certificate") {
		t.Fatalf("issue output: %s", out)
	}
	if fi, err := os.Stat(prefix + ".key"); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("key file mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if _, err := adminCmd(t, socket, "agent-cert", "issue", "--token", "edge", "--out", prefix); err == nil {
		t.Fatal("agent-cert issue overwrote an existing key")
	}
	if list := mustAdmin(t, socket, "token", "list"); !strings.Contains(list, "require-cert") {
		t.Fatalf("token list:\n%s", list)
	}

	// The issued files work as agent config, with no token at all.
	f, err := config.LoadAgentFile(writeFile(t, "agent.yaml", "relay: "+env.addr+"\nserver_name: "+controlSNI+
		"\nca: "+env.pki.caFile+"\ncert: "+prefix+".crt\nkey: "+prefix+".key\ntunnels:\n  - {type: tcp, target: \"127.0.0.1:1\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv(config.TokenEnv, "")
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	cfg.Proxy = transport.ProxyNone
	a, err := agent.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	waitReady(t, runAgent(t, a))
}

func TestCertConfigValidation(t *testing.T) {
	f, err := config.ParseAgentArgs([]string{"--relay", "r:443", "--cert", "/no/such.crt", "--key", "/no/such.key", "tcp", "22"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.AgentConfig(testLogger(), "test"); err == nil {
		t.Fatal("missing certificate files accepted")
	}
	f, _ = config.ParseAgentArgs([]string{"--relay", "r:443", "--cert", "x.crt", "tcp", "22"}, io.Discard)
	if _, err := f.AgentConfig(testLogger(), "test"); err == nil {
		t.Fatal("--cert without --key accepted")
	}
	t.Setenv(config.TokenEnv, "")
	f, _ = config.ParseAgentArgs([]string{"--relay", "r:443", "tcp", "22"}, io.Discard)
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.New(cfg); err == nil || !strings.Contains(err.Error(), "token or a client certificate") {
		t.Fatalf("no token and no certificate: %v", err)
	}
}
