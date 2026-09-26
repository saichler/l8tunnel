package tests

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/edge"
	"github.com/saichler/l8tunnel/go/types/tun"
)

const terminateDomain = "app.custom.test"

// terminateEdge serves terminateDomain on a TLS port, terminating with the
// test PKI and balancing over targets.
type terminateEdge struct {
	port int
	pki  *testPKI
	e    *edge.Edge
}

func newTerminateEdge(t *testing.T, scheme tun.EdgeBackendScheme, skipVerify bool, targets ...string) *terminateEdge {
	t.Helper()
	pki := newPKI(t)
	e, set := newTestEdge(t, &staticLive{})
	if err := set.Put("site", readFile(t, pki.certFile), readFile(t, pki.keyFile), []string{terminateDomain}); err != nil {
		t.Fatal(err)
	}
	port := freePort(t)
	e.Apply([]*tun.EdgeDomain{{DomainId: "t", Domain: terminateDomain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{{ForwardId: "f", ListenPort: int32(port), Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
			Targets: targets, Lb: tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN, BackendScheme: scheme, SkipVerify: skipVerify,
			Enabled: true}}}}, 1)
	return &terminateEdge{port: port, pki: pki, e: e}
}

// client is one keep-alive HTTP/1.1 client to the edge.
func (te *terminateEdge) client(t *testing.T) *http.Client {
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: caPoolFile(t, te.pki.caFile)}, MaxIdleConnsPerHost: 1,
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", localAddr(te.port))
		}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 10 * time.Second}
}

func (te *terminateEdge) url(path string) string { return "https://" + terminateDomain + path }

// countingBackend answers with its name and counts the connections the
// edge opens to it.
type countingBackend struct {
	srv   *httptest.Server
	mu    sync.Mutex
	conns int
}

func newCountingBackend(t *testing.T, name string) *countingBackend {
	b := &countingBackend{}
	b.srv = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, name) }))
	b.srv.Config.ConnState = func(_ net.Conn, s http.ConnState) {
		if s == http.StateNew {
			b.mu.Lock()
			b.conns++
			b.mu.Unlock()
		}
	}
	b.srv.Start()
	t.Cleanup(b.srv.Close)
	return b
}

func (b *countingBackend) connections() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.conns
}

// A TERMINATE forward balances each request, even when the client keeps
// one connection open, and reuses its connections to each backend.
func TestEdgeTerminateBalancesPerRequestAndReusesConnections(t *testing.T) {
	a := newCountingBackend(t, "A")
	b := newCountingBackend(t, "B")
	te := newTerminateEdge(t, tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTP, false,
		a.srv.Listener.Addr().String(), b.srv.Listener.Addr().String())
	c := te.client(t)
	counts := map[string]int{}
	for i := 0; i < 40; i++ {
		counts[get(t, c, te.url("/"))]++
	}
	if counts["A"] != 20 || counts["B"] != 20 {
		t.Fatalf("40 requests over one client connection: %v, want A=20 B=20", counts)
	}
	if a.connections() != 1 || b.connections() != 1 {
		t.Fatalf("backend connections A=%d B=%d, want one each (reused)", a.connections(), b.connections())
	}
}

// WebSocket upgrades pass through a TERMINATE forward.
func TestEdgeTerminateWebSocket(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") != "websocket" {
			http.Error(w, "upgrade required", http.StatusUpgradeRequired)
			return
		}
		conn, rw, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
		rw.Flush()
		io.Copy(conn, rw)
	}))
	t.Cleanup(srv.Close)
	te := newTerminateEdge(t, tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTP, false, srv.Listener.Addr().String())

	conn, err := tls.Dial("tcp", localAddr(te.port), &tls.Config{ServerName: terminateDomain,
		RootCAs: caPoolFile(t, te.pki.caFile), NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: %s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", terminateDomain)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("status %d, want 101", resp.StatusCode)
	}
	conn.Write([]byte("frame-bytes"))
	got := make([]byte, len("frame-bytes"))
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "frame-bytes" {
		t.Fatalf("echo over the upgraded connection: %q, %v", got, err)
	}
}

// An HTTPS backend's certificate is verified unless the forward sets
// skip_verify.
func TestEdgeTerminateVerifiesUpstreamCertificates(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "secure") }))
	t.Cleanup(srv.Close)
	target := srv.Listener.Addr().String()

	verify := newTerminateEdge(t, tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTPS, false, target)
	resp, err := verify.client(t).Get(verify.url("/"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadGateway {
		t.Fatalf("self-signed backend without skip_verify: status %d, want 502", resp.StatusCode)
	}

	skip := newTerminateEdge(t, tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTPS, true, target)
	if body := get(t, skip.client(t), skip.url("/")); body != "secure" {
		t.Fatalf("with skip_verify: %q", body)
	}
}

// Weighted round robin matches the weights within 5% over 1,000
// connections.
func TestEdgeWeightsOverAThousandConnections(t *testing.T) {
	names := []string{"A", "B", "C"}
	var targets []string
	for i, n := range names {
		addr, stop := startNamedServer(t, n)
		t.Cleanup(stop)
		targets = append(targets, fmt.Sprintf("%s*%d", addr, i+1))
	}
	e, _ := newTestEdge(t, &staticLive{})
	port := freePort(t)
	e.Apply([]*tun.EdgeDomain{tcpSite("w", "w.example.test", port, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN, targets...)}, 1)

	const total = 1000
	counts := map[string]int{}
	for i := 0; i < total; i++ {
		counts[whoAnswers(localAddr(port))]++
	}
	for i, n := range names {
		want := float64(total) * float64(i+1) / 6
		if got := float64(counts[n]); got < want*0.95 || got > want*1.05 {
			t.Fatalf("%s got %d of %d, want %.0f ±5%% (all: %v)", n, counts[n], total, want, counts)
		}
	}
}
