package tests

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/edge"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/tun"
)

func TestEdgeWeightedRoundRobinAndHealth(t *testing.T) {
	a, stopA := startNamedServer(t, "A")
	b, stopB := startNamedServer(t, "B")
	defer stopB()
	c, stopC := startNamedServer(t, "C")
	defer stopC()
	e, _ := newTestEdge(t, &staticLive{})
	port := freePort(t)
	d := tcpSite("s1", "db.example.test", port, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN, a, b+"*2", "!"+c)
	d.PortForwards[0].HealthType = tun.EdgeHealthType_EDGE_HEALTH_TYPE_TCP
	d.PortForwards[0].HealthInterval = 1
	e.Apply([]*tun.EdgeDomain{d}, 1)

	counts := map[string]int{}
	for i := 0; i < 30; i++ {
		counts[whoAnswers(localAddr(port))]++
	}
	// Weight 1 : 2, and the disabled member gets nothing.
	if counts["A"] != 10 || counts["B"] != 20 || counts["C"] != 0 {
		t.Fatalf("distribution %v, want A=10 B=20 C=0", counts)
	}

	// A goes down: the failed dial moves traffic on at once, and health
	// checks mark it down; it comes back when it recovers.
	stopA()
	for i := 0; i < 6; i++ {
		if got := whoAnswers(localAddr(port)); got != "B" {
			t.Fatalf("with A down, got %q", got)
		}
	}
	waitUntil(t, 10*time.Second, "A marked down", func() bool {
		for _, be := range e.Status().Backends {
			if be.Target == a {
				return !be.Healthy
			}
		}
		return false
	})
	defer restartOn(t, a, "A")()
	waitUntil(t, 10*time.Second, "A back", func() bool {
		for i := 0; i < 3; i++ {
			if whoAnswers(localAddr(port)) == "A" {
				return true
			}
		}
		return false
	})
}

func TestEdgeSourceHashAndLeastConn(t *testing.T) {
	a, stopA := startNamedServer(t, "A")
	defer stopA()
	b, stopB := startNamedServer(t, "B")
	defer stopB()
	e, _ := newTestEdge(t, &staticLive{})
	hashPort, lcPort := freePort(t), freePort(t)
	e.Apply([]*tun.EdgeDomain{
		tcpSite("h", "h.example.test", hashPort, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_SOURCE_HASH, a, b),
		tcpSite("l", "l.example.test", lcPort, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_LEAST_CONN, a, b),
	}, 1)
	first := whoAnswers(localAddr(hashPort))
	for i := 0; i < 10; i++ {
		if got := whoAnswers(localAddr(hashPort)); got != first {
			t.Fatalf("source hash moved the client from %s to %s", first, got)
		}
	}
	// Least connections: while one connection is held open, new ones go
	// to the other member.
	echo := startEchoServer(t)
	lc2 := freePort(t)
	e.Apply([]*tun.EdgeDomain{tcpSite("l2", "l2.example.test", lc2, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_LEAST_CONN, echo, a)}, 2)
	conn, err := net.Dial("tcp", localAddr(lc2))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("x"))
	buf := make([]byte, 1)
	conn.Read(buf) // the first member is the echo server, now busy
	for i := 0; i < 5; i++ {
		if got := whoAnswers(localAddr(lc2)); got != "A" {
			t.Fatalf("least connections sent a new connection to the busy member (%q)", got)
		}
	}
}

func TestEdgeTLSSitesShareAPort(t *testing.T) {
	pki := newPKI(t)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("terminated " + r.Proto + " xff=" + r.Header.Get("X-Forwarded-For") + " host=" + r.Host))
	}))
	defer backend.Close()
	tlsBackend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("passthrough")) }))
	defer tlsBackend.Close()

	e, set := newTestEdge(t, &staticLive{})
	if err := set.Put("site", readFile(t, pki.certFile), readFile(t, pki.keyFile), []string{"app.custom.test"}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	fwd := func(mode tun.EdgeForwardMode, scheme tun.EdgeBackendScheme, target string) *tun.EdgePortForward {
		return &tun.EdgePortForward{ForwardId: "f", ListenPort: int32(port), Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS, Mode: mode,
			TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS, Targets: []string{target}, BackendScheme: scheme, Enabled: true}
	}
	e.Apply([]*tun.EdgeDomain{
		{DomainId: "t", Domain: "app.custom.test", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
			PortForwards: []*tun.EdgePortForward{fwd(tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTP, backend.Listener.Addr().String())}},
		{DomainId: "p", Domain: "raw.example.test", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
			PortForwards: []*tun.EdgePortForward{fwd(tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, 0, tlsBackend.Listener.Addr().String())}},
	}, 1)

	client := func(h2 bool, roots bool) *http.Client {
		cfg := &tls.Config{InsecureSkipVerify: !roots}
		if roots {
			cfg.RootCAs = caPoolFile(t, pki.caFile)
		}
		tr := &http.Transport{TLSClientConfig: cfg, ForceAttemptHTTP2: h2,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				var d net.Dialer
				return d.DialContext(ctx, "tcp", localAddr(port))
			}}
		t.Cleanup(tr.CloseIdleConnections)
		return &http.Client{Transport: tr, Timeout: 10 * time.Second}
	}
	for _, h2 := range []bool{false, true} {
		body := get(t, client(h2, true), "https://app.custom.test/")
		want := "HTTP/1.1"
		if h2 {
			want = "HTTP/1.1" // the edge speaks HTTP/1.1 to backends; the client side is h2
		}
		if !strings.HasPrefix(body, "terminated "+want) || !strings.Contains(body, "xff=127.0.0.1") || !strings.Contains(body, "host=app.custom.test") {
			t.Fatalf("terminated site (h2=%v): %q", h2, body)
		}
	}
	// Passthrough: the client sees the backend's own certificate.
	if body := get(t, client(false, false), "https://raw.example.test/"); body != "passthrough" {
		t.Fatalf("passthrough site: %q", body)
	}
	// An unknown name gets a TLS alert.
	conn, err := tls.Dial("tcp", localAddr(port), &tls.Config{ServerName: "nobody.example.test", InsecureSkipVerify: true})
	if err == nil {
		conn.Close()
		t.Fatal("an unknown server name was served")
	}

	// No healthy backend: 503 from the edge.
	backend.Close()
	resp, err := client(false, true).Get("https://app.custom.test/")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusServiceUnavailable || resp.Header.Get("X-L8tunnel-Error") != "no-healthy-backend" {
		t.Fatalf("with the backend gone: status %d", resp.StatusCode)
	}
}

func TestEdgeHTTPHostRoutingAndIPLists(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("site " + r.Host)) }))
	defer backend.Close()
	e, _ := newTestEdge(t, &staticLive{})
	port := freePort(t)
	site := func(id, domain string, allow ...string) *tun.EdgeDomain {
		return &tun.EdgeDomain{DomainId: id, Domain: domain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true, AllowIps: allow,
			PortForwards: []*tun.EdgePortForward{{ForwardId: "f", ListenPort: int32(port), Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_HTTP,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
				Targets: []string{backend.Listener.Addr().String()}, Enabled: true}}}
	}
	e.Apply([]*tun.EdgeDomain{site("a", "www.example.test"), site("b", "lan.example.test", "10.0.0.0/8")}, 1)
	plain := &http.Client{Timeout: 5 * time.Second, Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, "tcp", localAddr(port))
	}}}
	if body := get(t, plain, "http://www.example.test/"); body != "site www.example.test" {
		t.Fatalf("HTTP by Host: %q", body)
	}
	for _, url := range []string{"http://lan.example.test/", "http://unknown.example.test/"} {
		resp, err := plain.Get(url)
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Fatalf("%s: status %d", url, resp.StatusCode)
			}
		}
	}
}

func TestEdgeListenersFollowTheDomains(t *testing.T) {
	a, stopA := startNamedServer(t, "A")
	defer stopA()
	e, _ := newTestEdge(t, &staticLive{})
	p1, p2 := freePort(t), freePort(t)
	busy, err := net.Listen("tcp", localAddr(p2))
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	e.Apply([]*tun.EdgeDomain{tcpSite("x", "x.example.test", p1, 0, a), tcpSite("y", "y.example.test", p2, 0, a)}, 7)
	if whoAnswers(localAddr(p1)) != "A" {
		t.Fatal("a new port forward didn't open its listener")
	}
	st := e.Status()
	var failed bool
	for _, l := range st.Listeners {
		if int(l.Port) == p2 && !l.Bound && l.Error != "" {
			failed = true
		}
	}
	if !failed || st.Version != 7 {
		t.Fatalf("status %+v", st)
	}
	e.Apply(nil, 8)
	if whoAnswers(localAddr(p1)) != "" {
		t.Fatal("a removed port forward kept listening")
	}
}

func TestEdgeInFrontOfARelay(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, trustedProxies: loopback})
	_, relayPort, _ := net.SplitHostPort(env.addr)
	relay := edge.RelayTarget{ID: "r0", IP: "127.0.0.1"}
	live := &staticLive{relays: []edge.RelayTarget{relay}, hosts: map[string]edge.RelayTarget{"web." + baseDomain: relay}}
	e, _ := newTestEdge(t, live)
	port := freePort(t)
	e.Apply([]*tun.EdgeDomain{{DomainId: "base", Domain: baseDomain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{{ForwardId: "https", ListenPort: int32(port), Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_RELAY, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS,
			TargetPort: int32(mustAtoi(t, relayPort)), Enabled: true}}}}, 1)

	// The agent reaches the relay through the edge (control name).
	edgeEnv := *env
	edgeEnv.addr = localAddr(port)
	startAgentOn(t, &edgeEnv, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})
	// A browser reaches the tunnel through the edge; the relay sees the
	// client's address from the edge's PROXY header.
	seen := getSeen(t, httpsClient(t, &edgeEnv, false), tunnelURL(&edgeEnv, "web", "/"), nil)
	if seen.XFF != "127.0.0.1" {
		t.Fatalf("X-Forwarded-For through the edge: %q", seen.XFF)
	}
}

func get(t *testing.T, c *http.Client, url string) string {
	t.Helper()
	resp, err := c.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return string(b)
}

func mustAtoi(t *testing.T, s string) int {
	t.Helper()
	n, err := net.LookupPort("tcp", s)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

// startAgentOn runs an agent against env's address (for example the edge).
func startAgentOn(t *testing.T, env *relayEnv, tunnels ...agent.TunnelConfig) *runningAgent {
	t.Helper()
	tlsCfg, err := transport.ClientTLSConfig(controlSNI, env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{RelayAddr: env.addr, TLS: tlsCfg, Token: testToken, Version: "test",
		Proxy: transport.ProxyNone, ReconnectMin: 50 * time.Millisecond, ReconnectMax: 200 * time.Millisecond,
		Logger: testLogger(), Tunnels: tunnels})
	if err != nil {
		t.Fatal(err)
	}
	return waitReady(t, runAgent(t, a))
}
