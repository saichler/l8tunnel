package tests

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/client"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// connectProxy is a minimal HTTP CONNECT proxy that counts tunnels.
type connectProxy struct {
	addr     string
	connects atomic.Int32
	mu       sync.Mutex
	targets  []string
}

// startConnectProxy starts a proxy; with user/password set it requires
// Basic proxy authentication.
func startConnectProxy(t *testing.T, user, password string) *connectProxy {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	p := &connectProxy{addr: ln.Addr().String()}
	wantAuth := ""
	if user != "" {
		wantAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+password))
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go p.serve(conn, wantAuth)
		}
	}()
	return p
}

func (p *connectProxy) serve(conn net.Conn, wantAuth string) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if req.Method != http.MethodConnect {
		io.WriteString(conn, "HTTP/1.1 405 Method Not Allowed\r\n\r\n")
		return
	}
	if wantAuth != "" && req.Header.Get("Proxy-Authorization") != wantAuth {
		io.WriteString(conn, "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n")
		return
	}
	target, err := net.Dial("tcp", req.Host)
	if err != nil {
		io.WriteString(conn, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
		return
	}
	defer target.Close()
	p.connects.Add(1)
	p.mu.Lock()
	p.targets = append(p.targets, req.Host)
	p.mu.Unlock()
	io.WriteString(conn, "HTTP/1.1 200 Connection established\r\n\r\n")
	go io.Copy(target, br)
	io.Copy(conn, target)
}

func TestWebSocketTransport(t *testing.T) {
	env := startRelay(t, 1)
	a := newAgentWith(t, env, func(c *agent.Config) {
		c.Transport = transport.TransportWebSocket
		c.Tunnels = []agent.TunnelConfig{
			{Name: "ws-tcp", Type: tcpType, Target: startEchoServer(t)},
			{Name: "ws-web", Type: httpType, Target: startInspectServer(t)},
		}
	})
	ra := waitReady(t, runAgent(t, a))

	payload := bytes.Repeat([]byte("websocket "), 100000) // 1 MB
	got, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), payload)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("round trip over the WebSocket transport: %d bytes, %v", len(got), err)
	}
	getSeen(t, httpsClient(t, env, false), tunnelURL(env, "ws-web", "/"), nil)
}

func TestAgentThroughHTTPProxy(t *testing.T) {
	env := startRelay(t, 2)
	proxy := startConnectProxy(t, "agent", "p@ss")
	for i, tr := range []string{transport.TransportTLS, transport.TransportWebSocket} {
		a := newAgentWith(t, env, func(c *agent.Config) {
			c.Transport = tr
			c.Proxy = "http://agent:p%40ss@" + proxy.addr
			c.Tunnels = []agent.TunnelConfig{{Type: tcpType, Target: startEchoServer(t)}}
		})
		ra := waitReady(t, runAgent(t, a))
		if got, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), []byte(tr)); err != nil || string(got) != tr {
			t.Fatalf("%s through the proxy: %q %v", tr, got, err)
		}
		if int(proxy.connects.Load()) != i+1 {
			t.Fatalf("%s: the proxy saw %d CONNECTs, want %d", tr, proxy.connects.Load(), i+1)
		}
	}
	proxy.mu.Lock()
	defer proxy.mu.Unlock()
	for _, target := range proxy.targets {
		if target != env.addr {
			t.Fatalf("CONNECT target %q, want the relay %q", target, env.addr)
		}
	}
}

func TestProxyRefusalIsReported(t *testing.T) {
	env := startRelay(t, 1)
	proxy := startConnectProxy(t, "agent", "secret")
	tlsCfg := mustClientTLS(t, env)
	_, err := transport.DialRelay(t.Context(), env.addr, tlsCfg, transport.DialOptions{Proxy: "http://agent:wrong@" + proxy.addr})
	if err == nil || !strings.Contains(err.Error(), "407") {
		t.Fatalf("wrong proxy credentials: %v, want a 407 error", err)
	}
	if err := transport.ParseProxy("socks5://x:1"); err == nil {
		t.Fatal("ParseProxy accepted a socks5 proxy")
	}
	if strings.Contains(err.Error(), "wrong") {
		t.Fatal("the proxy password leaked into the error message")
	}
}

func TestConnectThroughHTTPProxy(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "box", Type: sshType, Target: startEchoServer(t)})
	proxy := startConnectProxy(t, "", "")
	var out bytes.Buffer
	err := client.Connect(t.Context(), client.Config{Host: "box." + baseDomain, RelayAddr: env.addr,
		CAFile: env.pki.caFile, Proxy: "http://" + proxy.addr}, strings.NewReader("via proxy"), &out)
	if err != nil || out.String() != "via proxy" || proxy.connects.Load() != 1 {
		t.Fatalf("connect through the proxy: %q %v (connects %d)", out.String(), err, proxy.connects.Load())
	}
}

func scrape(t *testing.T, env *relayEnv) string {
	t.Helper()
	rec := httptest.NewRecorder()
	env.srv.MetricsHandler().ServeHTTP(rec, httptest.NewRequest("GET", "/metrics", nil))
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/plain; version=0.0.4") {
		t.Fatalf("metrics content type %q", ct)
	}
	return rec.Body.String()
}

func TestMetricsEndpoint(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, heartbeat: 50 * time.Millisecond})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "m", Type: tcpType, Target: startEchoServer(t)})
	if _, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), []byte("1234")); err != nil {
		t.Fatal(err)
	}
	err := runAgentExpectError(t, env, "l8t_00000000_wrongwrongwrongwrongwrongwrongwrongwrongwro",
		agent.TunnelConfig{Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, 1)
	connect(t, env, "nobody."+baseDomain, nil) // rejected: no route

	want := []string{
		`l8tunnel_agents_connected 1`,
		`l8tunnel_tunnels{type="tcp"} 1`,
		`l8tunnel_tunnel_connections_total{token="test",tunnel="m",type="tcp"} 1`,
		`l8tunnel_tunnel_bytes_in_total{token="test",tunnel="m",type="tcp"} 4`,
		`l8tunnel_tunnel_bytes_out_total{token="test",tunnel="m",type="tcp"} 4`,
		`l8tunnel_auth_failures_total 1`,
		`l8tunnel_connections_rejected_total{reason="no_route"} 1`,
		`# TYPE l8tunnel_tunnel_bytes_in_total counter`,
	}
	var text string
	waitUntil(t, 5*time.Second, "metrics", func() bool {
		text = scrape(t, env)
		for _, w := range want {
			if !strings.Contains(text, w) {
				return false
			}
		}
		// A heartbeat has reported a round trip by now.
		return strings.Contains(text, "l8tunnel_agent_rtt_seconds{agent=") && !strings.Contains(text, `"} 0`+"\n# HELP l8tunnel_tunnels ")
	})
	for _, w := range want {
		if !strings.Contains(text, w) {
			t.Errorf("metrics missing %q", w)
		}
	}
}

// syncBuffer is a goroutine-safe log sink.
type syncBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *syncBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *syncBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

func TestHTTPAccessLogAndConnectionLog(t *testing.T) {
	logs := &syncBuffer{}
	logger := slog.New(slog.NewJSONHandler(logs, nil))
	env := startRelayWith(t, relayOpts{ports: 1, accessLog: true, logger: logger})
	ra := startAgent(t, env,
		agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)},
		agent.TunnelConfig{Name: "raw", Type: tcpType, Target: startEchoServer(t)})
	getSeen(t, httpsClient(t, env, false), tunnelURL(env, "web", "/logged?x=1"), nil)
	if _, err := roundTrip(publicAddr(ra.agent.Endpoints()[1].GetPublicPort()), []byte("abc")); err != nil {
		t.Fatal(err)
	}

	var access, conn map[string]interface{}
	waitUntil(t, 5*time.Second, "log lines", func() bool {
		access, conn = nil, nil
		for _, line := range strings.Split(logs.String(), "\n") {
			var m map[string]interface{}
			if json.Unmarshal([]byte(line), &m) != nil {
				continue
			}
			switch m["msg"] {
			case "http request":
				access = m
			case "connection closed":
				if m["tunnel"] == "raw" {
					conn = m
				}
			}
		}
		return access != nil && conn != nil
	})
	if access["path"] != "/logged" || access["status"] != float64(200) || access["method"] != "GET" {
		t.Fatalf("access log line %v", access)
	}
	if conn["bytes_in"] != float64(3) || conn["client"] == nil || conn["duration_ms"] == nil {
		t.Fatalf("connection log line %v", conn)
	}
}

func TestLogConfig(t *testing.T) {
	var buf bytes.Buffer
	logger, err := config.LogFile{Format: "json", Level: "warn"}.NewLogger(&buf)
	if err != nil {
		t.Fatal(err)
	}
	logger.Info("hidden")
	logger.Warn("shown", "k", "v")
	var m map[string]interface{}
	if err := json.Unmarshal(buf.Bytes(), &m); err != nil || m["msg"] != "shown" || m["k"] != "v" {
		t.Fatalf("json warn logger wrote %q", buf.String())
	}
	for _, bad := range []config.LogFile{{Format: "xml"}, {Level: "loud"}} {
		if _, err := bad.NewLogger(io.Discard); err == nil {
			t.Errorf("%+v accepted", bad)
		}
	}
}

func TestTransportAndProxyConfig(t *testing.T) {
	f, err := config.ParseAgentArgs([]string{"--relay", "r:443", "--token", testToken, "--transport", "wss",
		"--proxy", "http://proxy:3128", "--log-format", "json", "--log-level", "debug", "tcp", "22"}, io.Discard)
	if err != nil {
		t.Fatal(err)
	}
	if f.Transport != "wss" || f.Proxy != "http://proxy:3128" || f.Log.Format != "json" || f.Log.Level != "debug" {
		t.Fatalf("parsed %+v", f)
	}
	cfg, err := f.AgentConfig(testLogger(), "test")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := agent.New(cfg); err != nil {
		t.Fatal(err)
	}
	for _, edit := range []func(*agent.Config){
		func(c *agent.Config) { c.Transport = "quic" },
		func(c *agent.Config) { c.Proxy = "socks5://p:1" },
		func(c *agent.Config) { c.Proxy = "proxy:3128" },
	} {
		bad := cfg
		edit(&bad)
		if _, err := agent.New(bad); err == nil {
			t.Errorf("agent.New accepted transport %q proxy %q", bad.Transport, bad.Proxy)
		}
	}

	pki := newPKI(t)
	sf, err := config.LoadServerFile(writeFile(t, "server.yaml", "base_domain: tunnel.test\ntls: {cert: "+pki.certFile+", key: "+pki.keyFile+"}\n"+
		"access_log: true\nmetrics: {listen: 127.0.0.1:9100}\nlog: {format: json, level: debug}\n"))
	if err != nil {
		t.Fatal(err)
	}
	rc, _, err := sf.RelayConfig(context.Background(), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	if !rc.AccessLog || sf.Metrics.Listen != "127.0.0.1:9100" || sf.Log.Format != "json" {
		t.Fatalf("server options: access_log=%v metrics=%q log=%+v", rc.AccessLog, sf.Metrics.Listen, sf.Log)
	}
}
