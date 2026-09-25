package tests

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

func expectRemoteCode(t *testing.T, err error, want l8tunnel.ErrorCode) {
	t.Helper()
	var rerr *protocol.RemoteError
	if !errors.As(err, &rerr) {
		t.Fatalf("expected a relay error %s, got %v", want, err)
	}
	if rerr.Code != want {
		t.Fatalf("relay error code = %s, want %s (%s)", rerr.Code, want, rerr.Message)
	}
}

func TestInvalidTokenRejected(t *testing.T) {
	env := startRelay(t, 1)
	err := runAgentExpectError(t, env, "wrong-token-0123456789",
		agent.TunnelConfig{Name: "x", Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
}

func TestPortOutsideRangeRejected(t *testing.T) {
	env := startRelay(t, 1)
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "x", Type: tcpType, Target: unusedAddr(t), PublicPort: uint32(env.portMax + 1)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED)
}

func TestPortRangeExhausted(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "first", Type: tcpType, Target: startEchoServer(t)})
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "second", Type: tcpType, Target: startEchoServer(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE)
}

func TestDuplicateNameRejected(t *testing.T) {
	env := startRelay(t, 2)
	startAgent(t, env, agent.TunnelConfig{Name: "dup", Type: tcpType, Target: startEchoServer(t)})
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "dup", Type: tcpType, Target: startEchoServer(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)
}

func TestInvalidNameRejected(t *testing.T) {
	env := startRelay(t, 1)
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "Not_A_Label", Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)
}

func TestFailedRegistrationRollsBackAllTunnels(t *testing.T) {
	env := startRelay(t, 2)
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "good", Type: tcpType, Target: startEchoServer(t)},
		agent.TunnelConfig{Name: "bad", Type: tcpType, Target: startEchoServer(t), PublicPort: 1})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED)
	// "good" was released, so another agent can take the name.
	startAgent(t, env, agent.TunnelConfig{Name: "good", Type: tcpType, Target: startEchoServer(t)})
}

func TestNonAgentALPNRejected(t *testing.T) {
	env := startRelay(t, 1)
	pem, err := os.ReadFile(env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(pem)
	conn, err := tls.Dial("tcp", env.addr, &tls.Config{
		ServerName: controlSNI, RootCAs: pool, NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		return // handshake refused: no shared application protocol
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if n, err := conn.Read(make([]byte, 1)); err == nil {
		t.Fatalf("relay kept a non-agent connection open (read %d bytes)", n)
	}
}

func TestAgentConfigFailsFast(t *testing.T) {
	tlsCfg, err := transport.ClientTLSConfig("localhost", "")
	if err != nil {
		t.Fatal(err)
	}
	good := agent.Config{
		RelayAddr: "localhost:443", TLS: tlsCfg, Token: testToken,
		Tunnels: []agent.TunnelConfig{{Type: tcpType, Target: "127.0.0.1:80"}},
	}
	if _, err := agent.New(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *agent.Config){
		"no token":         func(c *agent.Config) { c.Token = "" },
		"bad relay addr":   func(c *agent.Config) { c.RelayAddr = "localhost" },
		"no TLS":           func(c *agent.Config) { c.TLS = nil },
		"no tunnels":       func(c *agent.Config) { c.Tunnels = nil },
		"bad target":       func(c *agent.Config) { c.Tunnels = []agent.TunnelConfig{{Type: tcpType, Target: "nope"}} },
		"unsupported type": func(c *agent.Config) { c.Tunnels[0].Type = l8tunnel.TunnelType_TUNNEL_TYPE_HTTP },
		"unspecified type": func(c *agent.Config) { c.Tunnels[0].Type = l8tunnel.TunnelType_TUNNEL_TYPE_UNSPECIFIED },
		"reversed backoff": func(c *agent.Config) { c.ReconnectMin, c.ReconnectMax = time.Minute, time.Second },
		"duplicate names": func(c *agent.Config) {
			c.Tunnels = []agent.TunnelConfig{{Name: "a", Type: tcpType, Target: "h:1"}, {Name: "a", Type: tcpType, Target: "h:2"}}
		},
	}
	for name, mutate := range cases {
		cfg := good
		cfg.Tunnels = append([]agent.TunnelConfig(nil), good.Tunnels...)
		mutate(&cfg)
		if _, err := agent.New(cfg); err == nil {
			t.Errorf("%s: agent.New accepted an invalid config", name)
		}
	}
	if _, err := agent.ParseTunnelType("udp"); err == nil {
		t.Error("ParseTunnelType accepted udp")
	}
}

func TestRelayConfigFailsFast(t *testing.T) {
	pki := newPKI(t)
	tlsCfg, err := transport.ServerTLSConfig(pki.certFile, pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	tokens, err := auth.NewTokens(map[string]string{"t": testToken})
	if err != nil {
		t.Fatal(err)
	}
	good := relay.Config{ControlAddr: ":0", TLS: tlsCfg, Tokens: tokens, BaseDomain: baseDomain, TCPPortMin: 1000, TCPPortMax: 1001}
	if _, err := relay.New(good); err != nil {
		t.Fatalf("valid config rejected: %v", err)
	}
	cases := map[string]func(c *relay.Config){
		"no control addr": func(c *relay.Config) { c.ControlAddr = "" },
		"no TLS":          func(c *relay.Config) { c.TLS = nil },
		"no certificate":  func(c *relay.Config) { c.TLS = &tls.Config{} },
		"no tokens":       func(c *relay.Config) { c.Tokens = nil },
		"no base domain":  func(c *relay.Config) { c.BaseDomain = "" },
		"bare base":       func(c *relay.Config) { c.BaseDomain = "localhost" },
		"reversed range":  func(c *relay.Config) { c.TCPPortMin, c.TCPPortMax = 2000, 1000 },
		"negative grace":  func(c *relay.Config) { c.NameGracePeriod = -time.Second },
	}
	for name, mutate := range cases {
		cfg := good
		mutate(&cfg)
		if _, err := relay.New(cfg); err == nil {
			t.Errorf("%s: relay.New accepted an invalid config", name)
		}
	}

	if _, err := transport.ServerTLSConfig("", ""); err == nil {
		t.Error("ServerTLSConfig accepted missing files")
	}
	if _, err := auth.NewTokens(map[string]string{"short": "abc"}); err == nil {
		t.Error("NewTokens accepted a short token")
	}
	if _, err := auth.NewTokens(nil); err == nil {
		t.Error("NewTokens accepted an empty token set")
	}
	bad := filepath.Join(t.TempDir(), "tokens")
	os.WriteFile(bad, []byte("only-one-field\n"), 0o600)
	if _, err := auth.LoadTokensFile(bad); err == nil {
		t.Error("LoadTokensFile accepted a malformed line")
	}
	for _, r := range []string{"", "abc", "0-10", "10-5", "1-70000"} {
		if _, _, err := relay.ParsePortRange(r); err == nil {
			t.Errorf("ParsePortRange accepted %q", r)
		}
	}
	if lo, hi, err := relay.ParsePortRange("22000-22999"); err != nil || lo != 22000 || hi != 22999 {
		t.Errorf("ParsePortRange(22000-22999) = %d, %d, %v", lo, hi, err)
	}
}
