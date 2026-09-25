package tests

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
)

func writeFile(t *testing.T, name, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestAgentYAMLConfig(t *testing.T) {
	t.Setenv("MY_TUNNEL_TOKEN", testToken)
	path := writeFile(t, "agent.yaml", `
relay: connect.tunnel.test:443
token: ${MY_TUNNEL_TOKEN}
tunnels:
  - name: homebox
    type: ssh
  - name: db
    type: tcp
    target: 10.0.0.5:5432
    public_port: 22001
`)
	f, err := config.LoadAgentFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(f.Tunnels) != 2 || f.Tunnels[1].PublicPort != 22001 || f.Tunnels[1].Target != "10.0.0.5:5432" {
		t.Fatalf("unexpected tunnels %+v", f.Tunnels)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Token != testToken || cfg.TLS.ServerName != controlSNI {
		t.Fatalf("token %q / server name %q", cfg.Token, cfg.TLS.ServerName)
	}
	if _, err := agent.New(cfg); err != nil {
		t.Fatalf("agent.New rejected the YAML config: %v", err)
	}
}

func TestAgentYAMLRejectsBadFiles(t *testing.T) {
	cases := map[string]string{
		"unknown key":   "relay: r:443\ntunnels: []\nallow_ips: [1.2.3.4]\n",
		"unknown field": "relay: r:443\ntunnels:\n  - name: x\n    type: tcp\n    auth: {basic: {}}\n",
		"empty":         "",
		"bad yaml":      "relay: [\n",
	}
	for name, content := range cases {
		if _, err := config.LoadAgentFile(writeFile(t, "agent.yaml", content)); err == nil {
			t.Errorf("%s: LoadAgentFile accepted it", name)
		}
	}
	if _, err := config.LoadAgentFile(filepath.Join(t.TempDir(), "missing.yaml")); err == nil {
		t.Error("LoadAgentFile accepted a missing file")
	}

	f, err := config.LoadAgentFile(writeFile(t, "agent.yaml", "relay: r:443\ntoken: ${L8TUNNEL_TEST_UNSET_VAR}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.AgentConfig(testLogger(), "test"); err == nil || !strings.Contains(err.Error(), "L8TUNNEL_TEST_UNSET_VAR") {
		t.Fatalf("expected an error naming the unset variable, got %v", err)
	}
}

func TestAgentTokenFromEnvironment(t *testing.T) {
	t.Setenv(config.TokenEnv, testToken)
	f, err := config.ParseAgentArgs([]string{"--relay", "connect.tunnel.test:443", "ssh"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil || cfg.Token != testToken {
		t.Fatalf("token %q, err %v", cfg.Token, err)
	}
}

func TestAgentCommandLine(t *testing.T) {
	f, err := config.ParseAgentArgs([]string{"--relay", "r:443", "--token", "tok", "tcp", "5432", "--name", "db", "--port", "25432"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	want := config.TunnelFile{Name: "db", Type: "tcp", Target: "127.0.0.1:5432", PublicPort: 25432}
	if f.Relay != "r:443" || f.Token != "tok" || len(f.Tunnels) != 1 || f.Tunnels[0] != want {
		t.Fatalf("got %+v", f)
	}

	f, err = config.ParseAgentArgs([]string{"--relay", "r:443", "ssh", "--name", "homebox"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := f.Tunnels[0]; got.Type != "ssh" || got.Name != "homebox" || got.Target != "" {
		t.Fatalf("got %+v", got)
	}

	f, err = config.ParseAgentArgs([]string{"--relay", "r:443", "ssh", "10.0.0.5:2222"}, io.Discard)
	if err != nil || f.Tunnels[0].Target != "10.0.0.5:2222" {
		t.Fatalf("got %+v, err %v", f, err)
	}

	bad := [][]string{
		{},
		{"--config", "x.yaml", "tcp", "1"},
		{"--config", "x.yaml", "--relay", "r:443"},
		{"tcp", "70000"},
		{"tcp", "not-a-target"},
		{"tcp", "5432", "extra"},
		{"tcp", "5432", "--port", "70000"},
		{"--bogus"},
	}
	for _, args := range bad {
		if _, err := config.ParseAgentArgs(args, io.Discard); err == nil {
			t.Errorf("ParseAgentArgs(%q) succeeded", args)
		}
	}
}

func TestServerYAMLConfig(t *testing.T) {
	pki := newPKI(t)
	tokens := writeFile(t, "tokens", "test "+testToken+"\n")
	path := writeFile(t, "server.yaml", `
base_domain: tunnel.test
listen:
  https: 127.0.0.1:0
bind: 127.0.0.1
tcp_port_range: "30000-30010"
tls:
  cert: `+pki.certFile+`
  key: `+pki.keyFile+`
tokens_file: `+tokens+`
heartbeat_interval: 150ms
name_grace_period: 2m
`)
	f, err := config.LoadServerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.RelayConfig(testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HeartbeatInterval != 150*time.Millisecond || cfg.NameGracePeriod != 2*time.Minute ||
		cfg.TCPPortMin != 30000 || cfg.TCPPortMax != 30010 {
		t.Fatalf("unexpected relay config %+v", cfg)
	}
	if _, err := relay.New(cfg); err != nil {
		t.Fatalf("relay.New rejected the YAML config: %v", err)
	}

	for name, content := range map[string]string{
		"unsupported acme": "base_domain: tunnel.test\nacme: {email: a@b.c}\n",
		"bad duration":     "base_domain: tunnel.test\nheartbeat_interval: soon\n",
	} {
		if _, err := config.LoadServerFile(writeFile(t, "server.yaml", content)); err == nil {
			t.Errorf("%s: LoadServerFile accepted it", name)
		}
	}
	f, err = config.LoadServerFile(writeFile(t, "server.yaml", "base_domain: tunnel.test\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.RelayConfig(testLogger()); err == nil {
		t.Error("RelayConfig accepted a config without TLS files or tokens")
	}
}

// The shipped examples must stay loadable by this version's strict parser.
func TestDeployExamplesParse(t *testing.T) {
	examples := filepath.Join("..", "..", "deploy", "examples")
	if _, err := config.LoadServerFile(filepath.Join(examples, "server.yaml")); err != nil {
		t.Error(err)
	}
	t.Setenv(config.TokenEnv, testToken)
	f, err := config.LoadAgentFile(filepath.Join(examples, "agent.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.New(cfg); err != nil {
		t.Error(err)
	}
}
