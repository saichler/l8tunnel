package tests

import (
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
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
	if f.Relay != "r:443" || f.Token != "tok" || len(f.Tunnels) != 1 || !reflect.DeepEqual(f.Tunnels[0], want) {
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
	path := writeFile(t, "server.yaml", `
base_domain: tunnel.test
listen:
  https: 127.0.0.1:0
bind: 127.0.0.1
tcp_port_range: "30000-30010"
tls:
  cert: `+pki.certFile+`
  key: `+pki.keyFile+`
heartbeat_interval: 150ms
name_grace_period: 2m
`)
	f, err := config.LoadServerFile(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := f.RelayConfig(t.Context(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HeartbeatInterval != 150*time.Millisecond || cfg.NameGracePeriod != 2*time.Minute ||
		cfg.TCPPortMin != 30000 || cfg.TCPPortMax != 30010 {
		t.Fatalf("unexpected relay config %+v", cfg)
	}
	if _, err := f.NewRelay(t.Context(), testLogger(), newTestStore(t, auth.Policy{}), "test"); err != nil {
		t.Fatalf("NewRelay rejected the YAML config: %v", err)
	}

	for name, content := range map[string]string{
		"unknown acme key": "base_domain: tunnel.test\nacme: {email: a@b.c, provider: x}\n",
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
	if _, _, err := f.RelayConfig(t.Context(), testLogger()); err == nil {
		t.Error("RelayConfig accepted a config without certificates")
	}
}

// The shipped examples must stay loadable by this version's strict parser.
func TestDeployExamplesParse(t *testing.T) {
	examples := filepath.Join("..", "..", "deploy", "examples")
	if _, err := config.LoadServerFile(filepath.Join(examples, "server.yaml")); err != nil {
		t.Error(err)
	}
	t.Setenv(config.TokenEnv, testToken)
	t.Setenv("BACKUP_ACCESS_TOKEN", "example")
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

func TestHTTPTunnelTargets(t *testing.T) {
	f, err := config.LoadAgentFile(writeFile(t, "agent.yaml", `
relay: connect.tunnel.test:443
token: `+testToken+`
tunnels:
  - {name: app, type: http, target: "3000"}
  - {name: dev, type: http, target: "https://localhost:8443", insecure_skip_verify: true}
  - {name: plain, type: http, target: "http://10.0.0.7"}
  - {name: secure, type: http, target: "https://nas.lan"}
  - {name: pt, type: tls, target: "10.0.0.8:443"}
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	want := []agent.TunnelConfig{
		{Name: "app", Type: httpType, Target: "127.0.0.1:3000"},
		{Name: "dev", Type: httpType, Target: "localhost:8443", TargetTLS: true, InsecureSkipVerify: true},
		{Name: "plain", Type: httpType, Target: "10.0.0.7:80"},
		{Name: "secure", Type: httpType, Target: "nas.lan:443", TargetTLS: true},
		{Name: "pt", Type: l8tunnel.TunnelType_TUNNEL_TYPE_TLS, Target: "10.0.0.8:443"},
	}
	for i, w := range want {
		if !reflect.DeepEqual(cfg.Tunnels[i], w) {
			t.Errorf("tunnel %d = %+v, want %+v", i, cfg.Tunnels[i], w)
		}
	}
	if _, err := agent.New(cfg); err != nil {
		t.Fatal(err)
	}

	for name, tunnel := range map[string]string{
		"scheme on tcp":    `{type: tcp, target: "http://h:1"}`,
		"path in target":   `{type: http, target: "http://h:1/app"}`,
		"ftp scheme":       `{type: http, target: "ftp://h:1"}`,
		"insecure on http": `{type: http, target: "h:1", insecure_skip_verify: true}`,
		"port on http":     `{type: http, target: "h:1", public_port: 22001}`,
	} {
		f, err := config.LoadAgentFile(writeFile(t, "agent.yaml",
			"relay: r:443\ntoken: "+testToken+"\ntunnels:\n  - "+tunnel+"\n"))
		if err != nil {
			t.Fatal(err)
		}
		cfg, err := f.AgentConfig(testLogger(), "test")
		if err == nil {
			_, err = agent.New(cfg)
		}
		if err == nil {
			t.Errorf("%s: accepted", name)
		}
	}

	cli, err := config.ParseAgentArgs([]string{"--relay", "r:443", "http", "https://localhost:8443", "--insecure-skip-verify", "--name", "dev"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if got := cli.Tunnels[0]; got.Target != "https://localhost:8443" || !got.InsecureSkipVerify || got.Name != "dev" {
		t.Fatalf("CLI http tunnel %+v", got)
	}
}

func TestServerHTTPOptions(t *testing.T) {
	pki := newPKI(t)
	base := "base_domain: tunnel.test\ntls: {cert: " + pki.certFile + ", key: " + pki.keyFile + "}\n"

	cfg := relayConfigFromYAML(t, base)
	if cfg.HTTPAddr != ":80" || cfg.DisableForwardedHeaders || cfg.PublicHTTPSPort != 0 {
		t.Fatalf("defaults: %q %v %d", cfg.HTTPAddr, cfg.DisableForwardedHeaders, cfg.PublicHTTPSPort)
	}
	cfg = relayConfigFromYAML(t, base+"listen: {http: \"off\"}\nforwarded_headers: false\npublic_https_port: 8443\n")
	if cfg.HTTPAddr != "" || !cfg.DisableForwardedHeaders || cfg.PublicHTTPSPort != 8443 {
		t.Fatalf("overrides: %q %v %d", cfg.HTTPAddr, cfg.DisableForwardedHeaders, cfg.PublicHTTPSPort)
	}
}

func relayConfigFromYAML(t *testing.T, content string) relay.Config {
	t.Helper()
	f, err := config.LoadServerFile(writeFile(t, "server.yaml", content))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := f.RelayConfig(t.Context(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// Certificate misconfigurations must stop the relay before it touches the
// network, naming the setting at fault.
func TestCertificateConfigFailsFast(t *testing.T) {
	pki := newPKI(t)
	base := "base_domain: tunnel.test\n"
	static := "tls: {cert: " + pki.certFile + ", key: " + pki.keyFile + "}\n"
	cases := map[string]struct{ yaml, want string }{
		"neither":         {"", "either tls"},
		"both":            {static + "acme: {mode: dns01, email: a@b.c}\n", "not both"},
		"bad mode":        {"acme: {mode: tls-alpn, email: a@b.c}\n", "acme.mode"},
		"no email":        {"acme: {mode: dns01, dns_provider: cloudflare}\n", "acme.email"},
		"no provider":     {"acme: {mode: dns01, email: a@b.c}\n", "acme.dns_provider"},
		"bad provider":    {"acme: {mode: dns01, email: a@b.c, dns_provider: nope}\n", "not supported"},
		"no token":        {"acme: {mode: dns01, email: a@b.c, dns_provider: cloudflare}\n", "api_token"},
		"typo credential": {"acme: {mode: dns01, email: a@b.c, dns_provider: cloudflare, dns_credentials: {api_token: x, zone: y}}\n", "dns_credentials.zone"},
		"unset env":       {"acme: {mode: dns01, email: a@b.c, dns_provider: cloudflare, dns_credentials: {api_token: \"${L8TUNNEL_TEST_UNSET}\"}}\n", "L8TUNNEL_TEST_UNSET"},
		"http01 no :80":   {"listen: {http: \"off\"}\nacme: {mode: http01, email: a@b.c}\n", "listen.http"},
		"http01 with dns": {"acme: {mode: http01, email: a@b.c, dns_provider: cloudflare}\n", "only to mode dns01"},
		"http01 port 0":   {"listen: {http: 127.0.0.1:0}\nacme: {mode: http01, email: a@b.c}\n", "fixed port"},
		"bad ca_root":     {"acme: {mode: http01, email: a@b.c, ca_root: /nonexistent.pem}\n", "acme.ca_root"},
	}
	for name, c := range cases {
		f, err := config.LoadServerFile(writeFile(t, "server.yaml", base+c.yaml))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		_, _, err = f.RelayConfig(t.Context(), testLogger())
		if err == nil || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: got error %v, want one mentioning %q", name, err, c.want)
		}
	}
}

func TestAgentAccessConfig(t *testing.T) {
	t.Setenv("VAULT_TOKEN", "sesame")
	h, err := auth.HashPassword("pw")
	if err != nil {
		t.Fatal(err)
	}
	f, err := config.LoadAgentFile(writeFile(t, "agent.yaml", `
relay: connect.tunnel.test:443
token: `+testToken+`
status_socket: /run/l8tunnel-agent/status.sock
tunnels:
  - name: admin
    type: http
    target: 8080
    allow_ips: [203.0.113.0/24, 198.51.100.7]
    deny_ips: [203.0.113.66]
    basic_auth:
      - {user: alice, password_hash: "`+h+`"}
  - name: vault
    type: ssh
    access_token: ${VAULT_TOKEN}
`))
	if err != nil {
		t.Fatal(err)
	}
	if f.StatusSocket != "/run/l8tunnel-agent/status.sock" {
		t.Fatalf("status socket %q", f.StatusSocket)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	admin, vault := cfg.Tunnels[0], cfg.Tunnels[1]
	if len(admin.AllowIPs) != 2 || admin.DenyIPs[0] != "203.0.113.66" || admin.BasicUsers[0].Username != "alice" {
		t.Fatalf("admin tunnel %+v", admin)
	}
	if vault.AccessToken != "sesame" {
		t.Fatalf("vault access token %q", vault.AccessToken)
	}
	if _, err := agent.New(cfg); err != nil {
		t.Fatal(err)
	}

	cli, err := config.ParseAgentArgs([]string{"--relay", "r:443", "--status-socket", "/tmp/s.sock", "http", "8080",
		"--allow-ip", "10.0.0.0/8", "--allow-ip", "192.168.1.5", "--deny-ip", "10.0.0.9", "--basic-auth", "bob:" + h}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	tun := cli.Tunnels[0]
	if cli.StatusSocket != "/tmp/s.sock" || len(tun.AllowIPs) != 2 || tun.DenyIPs[0] != "10.0.0.9" ||
		tun.BasicAuth[0].User != "bob" || tun.BasicAuth[0].PasswordHash != h {
		t.Fatalf("CLI access flags: %+v", cli)
	}
	if _, err := config.ParseAgentArgs([]string{"--relay", "r:443", "http", "8080", "--basic-auth", "no-colon"}, io.Discard); err == nil {
		t.Fatal("--basic-auth without user:hash accepted")
	}
}

func TestServerStorageAdminAndRateLimits(t *testing.T) {
	pki := newPKI(t)
	base := "base_domain: tunnel.test\ntls: {cert: " + pki.certFile + ", key: " + pki.keyFile + "}\n"
	f, err := config.LoadServerFile(writeFile(t, "server.yaml", base))
	if err != nil {
		t.Fatal(err)
	}
	if f.DatabasePath() != "/var/lib/l8tunnel/l8tunnel.db" || f.AdminSocket() != "/run/l8tunnel/admin.sock" {
		t.Fatalf("defaults: %s %s", f.DatabasePath(), f.AdminSocket())
	}
	f, err = config.LoadServerFile(writeFile(t, "server.yaml", base+`
storage: /srv/l8
admin: {socket: /tmp/l8.sock}
rate_limits: {connections_per_second: 5, connections_burst: 10, auth_failures_per_minute: 3}
`))
	if err != nil {
		t.Fatal(err)
	}
	cfg, _, err := f.RelayConfig(t.Context(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if f.DatabasePath() != "/srv/l8/l8tunnel.db" || f.AdminSocket() != "/tmp/l8.sock" ||
		cfg.RateLimits.ConnectionsPerSecond != 5 || cfg.RateLimits.ConnectionsBurst != 10 || cfg.RateLimits.AuthFailuresPerMinute != 3 {
		t.Fatalf("overrides: %s %s %+v", f.DatabasePath(), f.AdminSocket(), cfg.RateLimits)
	}
	if _, err := config.LoadServerFile(writeFile(t, "server.yaml", base+"tokens_file: /etc/tokens\n")); err == nil {
		t.Fatal("the removed tokens_file option was accepted silently")
	}
}
