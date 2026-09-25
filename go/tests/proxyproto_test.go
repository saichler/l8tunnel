package tests

import (
	"context"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	proxyproto "github.com/pires/go-proxyproto"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
)

var loopback = []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}

// proxyHeader is a PROXY v2 header claiming the connection came from
// client (an edge proxy in front of the relay sends one).
func proxyHeader(t *testing.T, client string) []byte {
	t.Helper()
	h := proxyproto.HeaderProxyFromAddrs(2,
		net.TCPAddrFromAddrPort(netip.MustParseAddrPort(client)),
		net.TCPAddrFromAddrPort(netip.MustParseAddrPort("192.0.2.1:443")))
	b, err := h.Format()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// dialWithHeader connects to addr and sends header first (nil: none).
func dialWithHeader(ctx context.Context, addr string, header []byte) (net.Conn, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	if header != nil {
		if _, err := conn.Write(header); err != nil {
			conn.Close()
			return nil, err
		}
	}
	return conn, nil
}

// proxiedHTTPSClient is httpsClient whose connections start with header.
func proxiedHTTPSClient(t *testing.T, env *relayEnv, header []byte) *http.Client {
	t.Helper()
	client := httpsClient(t, env, false)
	client.Transport.(*http.Transport).DialContext = func(ctx context.Context, _, _ string) (net.Conn, error) {
		return dialWithHeader(ctx, env.addr, header)
	}
	return client
}

// proxiedRoundTrip is roundTrip on a connection that starts with header.
func proxiedRoundTrip(addr string, header, payload []byte) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := dialWithHeader(ctx, addr, header)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write(payload); err != nil {
		return nil, err
	}
	conn.(*net.TCPConn).CloseWrite()
	return io.ReadAll(conn)
}

func TestProxyProtocolFromTrustedProxyGivesTheClientIP(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, trustedProxies: loopback})
	startAgent(t, env,
		agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)},
		agent.TunnelConfig{Name: "lan", Type: httpType, Target: startInspectServer(t), AllowIPs: []string{"203.0.113.0/24"}},
	)
	header := proxyHeader(t, "203.0.113.7:51000")

	seen := getSeen(t, proxiedHTTPSClient(t, env, header), tunnelURL(env, "web", "/"), nil)
	if seen.XFF != "203.0.113.7" {
		t.Fatalf("X-Forwarded-For %q, want the client IP from the PROXY header", seen.XFF)
	}
	// The tunnel's allow list sees the client IP from the header.
	getSeen(t, proxiedHTTPSClient(t, env, header), tunnelURL(env, "lan", "/"), nil)
	// A trusted source without a header keeps its own address.
	expectErrorPage(t, httpsClient(t, env, false), tunnelURL(env, "lan", "/"), http.StatusForbidden, "ip-denied")
	seen = getSeen(t, httpsClient(t, env, false), tunnelURL(env, "web", "/"), nil)
	if seen.XFF != "127.0.0.1" {
		t.Fatalf("X-Forwarded-For without a header %q", seen.XFF)
	}
}

func TestProxyProtocolOnModeAPorts(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, trustedProxies: loopback})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "db", Type: tcpType, Target: startEchoServer(t), AllowIPs: []string{"203.0.113.0/24"}})
	addr := publicAddr(ra.agent.Endpoints()[0].GetPublicPort())
	if got, err := proxiedRoundTrip(addr, proxyHeader(t, "203.0.113.9:40000"), []byte("hello")); err != nil || string(got) != "hello" {
		t.Fatalf("an allowed client behind the proxy was refused: %q %v", got, err)
	}
	if !refused(addr) {
		t.Fatal("a client outside the allow list got through without a PROXY header")
	}
}

func TestProxyHeaderFromUntrustedSourceIsRefused(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, trustedProxies: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})

	// A client can't claim another address by sending a header itself.
	_, err := proxiedHTTPSClient(t, env, proxyHeader(t, "203.0.113.7:51000")).Get(tunnelURL(env, "web", "/"))
	if err == nil {
		t.Fatal("a PROXY header from an untrusted address was accepted")
	}
	seen := getSeen(t, httpsClient(t, env, false), tunnelURL(env, "web", "/"), nil)
	if seen.XFF != "127.0.0.1" {
		t.Fatalf("X-Forwarded-For %q", seen.XFF)
	}
}

func TestProxyHeaderIgnoredWhenNoProxyIsTrusted(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})
	// Without trusted proxies the relay doesn't parse PROXY headers at all:
	// the header bytes aren't a TLS ClientHello, so the connection fails.
	conn, err := dialWithHeader(t.Context(), env.addr, proxyHeader(t, "203.0.113.7:51000"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	tconn := tls.Client(conn, &tls.Config{ServerName: "web." + baseDomain, RootCAs: caPool(t, env)})
	tconn.SetDeadline(time.Now().Add(5 * time.Second))
	if err := tconn.Handshake(); err == nil {
		t.Fatal("handshake succeeded after a PROXY header with no trusted proxies")
	}
}

func TestHealthAndReadinessEndpoints(t *testing.T) {
	env := startRelay(t, 1)
	probe := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		env.srv.OpsHandler().ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, strings.TrimSpace(rec.Body.String())
	}
	if code, body := probe("/healthz"); code != http.StatusOK || body != "ok" {
		t.Fatalf("/healthz %d %q", code, body)
	}
	if code, body := probe("/readyz"); code != http.StatusOK || body != "ok" {
		t.Fatalf("/readyz %d %q", code, body)
	}
	if code, body := probe("/metrics"); code != http.StatusOK || !strings.Contains(body, "l8tunnel_agents_connected") {
		t.Fatalf("/metrics %d", code)
	}
	env.srv.Close()
	if code, body := probe("/readyz"); code != http.StatusServiceUnavailable || body != "shutting down" {
		t.Fatalf("/readyz after Close %d %q", code, body)
	}
	if code, _ := probe("/healthz"); code != http.StatusOK {
		t.Fatalf("/healthz after Close %d", code)
	}
}
