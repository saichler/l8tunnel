package tests

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var httpType = l8tunnel.TunnelType_TUNNEL_TYPE_HTTP

// seenRequest is what the backend reports about the request it received.
type seenRequest struct {
	Method, Host, URI, XFF, XFHost, XFProto string
}

func startInspectServer(t *testing.T) string {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(seenRequest{
			Method: r.Method, Host: r.Host, URI: r.RequestURI,
			XFF: r.Header.Get("X-Forwarded-For"), XFHost: r.Header.Get("X-Forwarded-Host"),
			XFProto: r.Header.Get("X-Forwarded-Proto"),
		})
	}))
	t.Cleanup(srv.Close)
	return srv.Listener.Addr().String()
}

func getSeen(t *testing.T, client *http.Client, url string, header http.Header) seenRequest {
	t.Helper()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		t.Fatal(err)
	}
	for k, v := range header {
		req.Header[k] = v
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d (%s)", resp.StatusCode, resp.Header.Get(httpproxy.ErrorHeader))
	}
	var seen seenRequest
	if err := json.NewDecoder(resp.Body).Decode(&seen); err != nil {
		t.Fatal(err)
	}
	return seen
}

func TestHTTPTunnelProxiesRequestsWithForwardedHeaders(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})
	ep := ra.agent.Endpoints()[0]
	if want := tunnelURL(env, "web", ""); ep.GetPublicAddress() != want || ep.GetPublicPort() != 0 {
		t.Fatalf("endpoint %v, want public address %s and no port", ep, want)
	}

	url := tunnelURL(env, "web", "/path?q=1")
	seen := getSeen(t, httpsClient(t, env, false), url, http.Header{"X-Forwarded-For": {"6.6.6.6"}})
	host := strings.TrimPrefix(tunnelURL(env, "web", ""), "https://")
	want := seenRequest{Method: "GET", Host: host, URI: "/path?q=1", XFF: "127.0.0.1", XFHost: host, XFProto: "https"}
	if seen != want {
		t.Fatalf("backend saw %+v, want %+v", seen, want)
	}
}

func TestForwardedHeadersCanBeDisabled(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, noForwarded: true})
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})
	seen := getSeen(t, httpsClient(t, env, false), tunnelURL(env, "web", "/"), http.Header{"X-Forwarded-For": {"6.6.6.6"}})
	if seen.XFF != "" || seen.XFProto != "" || seen.XFHost != "" {
		t.Fatalf("backend saw forwarded headers %+v", seen)
	}
}

func TestHTTPTunnelServesHTTP2(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})
	resp, err := httpsClient(t, env, true).Get(tunnelURL(env, "web", "/"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.ProtoMajor != 2 {
		t.Fatalf("status %d over %s, want 200 over HTTP/2", resp.StatusCode, resp.Proto)
	}
}

func TestHTTPTunnelLargeUpload(t *testing.T) {
	env := startRelay(t, 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		io.Copy(h, r.Body)
		io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
	}))
	t.Cleanup(srv.Close)
	startAgent(t, env, agent.TunnelConfig{Name: "up", Type: httpType, Target: srv.Listener.Addr().String()})

	payload := make([]byte, 8<<20)
	rand.Read(payload)
	sum := sha256.Sum256(payload)
	for _, h2 := range []bool{false, true} {
		resp, err := httpsClient(t, env, h2).Post(tunnelURL(env, "up", "/"), "application/octet-stream", bytes.NewReader(payload))
		if err != nil {
			t.Fatal(err)
		}
		got, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if string(got) != hex.EncodeToString(sum[:]) {
			t.Fatalf("h2=%v: backend hash %s, want %x", h2, got, sum)
		}
	}
}

func TestHTTPTunnelStreamsResponsesWithoutBuffering(t *testing.T) {
	env := startRelay(t, 1)
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/event-stream")
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: second\n\n")
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	startAgent(t, env, agent.TunnelConfig{Name: "sse", Type: httpType, Target: srv.Listener.Addr().String()})

	resp, err := httpsClient(t, env, false).Get(tunnelURL(env, "sse", "/"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	lines := bufio.NewReader(resp.Body)
	// The first event must arrive while the backend is still blocked.
	if line, err := lines.ReadString('\n'); err != nil || line != "data: first\n" {
		t.Fatalf("first event: %q, %v", line, err)
	}
	close(release)
	rest, _ := io.ReadAll(lines)
	if !strings.Contains(string(rest), "data: second") {
		t.Fatalf("second event missing: %q", rest)
	}
}

func TestHTTPTunnelWebSocketUpgrade(t *testing.T) {
	env := startRelay(t, 1)
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
		io.Copy(conn, rw) // echo raw frames
	}))
	t.Cleanup(srv.Close)
	startAgent(t, env, agent.TunnelConfig{Name: "ws", Type: httpType, Target: srv.Listener.Addr().String()})

	conn, err := tls.Dial("tcp", env.addr, &tls.Config{
		ServerName: "ws." + baseDomain, RootCAs: caPool(t, env), NextProtos: []string{"http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /socket HTTP/1.1\r\nHost: ws.%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"+
		"Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", baseDomain)
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
		t.Fatalf("echo over upgraded connection: %q, %v", got, err)
	}
}

func TestHTTPSTargetWithSelfSignedCertificate(t *testing.T) {
	env := startRelay(t, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "secure backend")
	}))
	t.Cleanup(srv.Close)
	target := srv.Listener.Addr().String()
	startAgent(t, env,
		agent.TunnelConfig{Name: "skip", Type: httpType, Target: target, TargetTLS: true, InsecureSkipVerify: true},
		agent.TunnelConfig{Name: "verify", Type: httpType, Target: target, TargetTLS: true},
	)
	client := httpsClient(t, env, false)

	resp, err := client.Get(tunnelURL(env, "skip", "/"))
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || string(body) != "secure backend" {
		t.Fatalf("skip-verify tunnel: %d %q", resp.StatusCode, body)
	}

	// Without skip-verify the self-signed certificate is rejected.
	expectErrorPage(t, client, tunnelURL(env, "verify", "/"), http.StatusBadGateway, "upstream-error")
}

func expectErrorPage(t *testing.T, client *http.Client, url string, status int, reason string) {
	t.Helper()
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != status || resp.Header.Get(httpproxy.ErrorHeader) != reason {
		t.Fatalf("%s: got %d / %q, want %d / %q", url, resp.StatusCode, resp.Header.Get(httpproxy.ErrorHeader), status, reason)
	}
	if !strings.Contains(string(body), "l8tunnel") || !strings.HasPrefix(resp.Header.Get("Content-Type"), "text/html") {
		t.Fatalf("%s: expected the HTML error page, got %q", url, body)
	}
}

func TestHTTPErrorPages(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env,
		agent.TunnelConfig{Name: "gone", Type: httpType, Target: startInspectServer(t)},
		agent.TunnelConfig{Name: "down", Type: httpType, Target: unusedAddr(t)},
	)
	client := httpsClient(t, env, false)

	expectErrorPage(t, client, tunnelURL(env, "nothing", "/"), http.StatusNotFound, "tunnel-not-found")
	expectErrorPage(t, client, tunnelURL(env, "down", "/"), http.StatusBadGateway, "upstream-error")

	stopAgent(t, ra)
	client.Transport.(*http.Transport).CloseIdleConnections()
	expectErrorPage(t, client, tunnelURL(env, "gone", "/"), http.StatusBadGateway, "agent-offline")
}

func TestHTTPHostMustMatchSNI(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env,
		agent.TunnelConfig{Name: "a", Type: httpType, Target: startInspectServer(t)},
		agent.TunnelConfig{Name: "b", Type: httpType, Target: startInspectServer(t)},
	)
	client := httpsClient(t, env, false)
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "a." + baseDomain
	expectErrorPage(t, client, tunnelURL(env, "b", "/"), http.StatusMisdirectedRequest, "misdirected")
}

func TestTLSPassthroughKeepsEndToEndEncryption(t *testing.T) {
	env := startRelay(t, 1)
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "passthrough")
	}))
	t.Cleanup(srv.Close)
	ra := startAgent(t, env, agent.TunnelConfig{
		Name: "pt", Type: l8tunnel.TunnelType_TUNNEL_TYPE_TLS, Target: srv.Listener.Addr().String(),
	})
	_, port, _ := net.SplitHostPort(env.addr)
	if got, want := ra.agent.Endpoints()[0].GetPublicAddress(), "pt."+baseDomain+":"+port; got != want {
		t.Fatalf("public address %q, want %q", got, want)
	}

	pool := srv.Client().Transport.(*http.Transport).TLSClientConfig.RootCAs
	conn, err := tls.Dial("tcp", env.addr, &tls.Config{
		ServerName: "pt." + baseDomain, RootCAs: pool, InsecureSkipVerify: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	// The client sees the backend's own certificate, not the relay's.
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, srv.Certificate().Raw) {
		t.Fatal("the certificate presented is not the backend's")
	}
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: pt.%s\r\nConnection: close\r\n\r\n", baseDomain)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK || string(body) != "passthrough" {
		t.Fatalf("passthrough response: %d %q", resp.StatusCode, body)
	}
}

func TestPlainHTTPRedirectsToHTTPS(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, httpListener: true})
	client := &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	req, _ := http.NewRequest("POST", "http://"+env.srv.HTTPAddr()+"/some/path?q=1", nil)
	req.Host = "web." + baseDomain
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if want := tunnelURL(env, "web", "/some/path?q=1"); resp.StatusCode != http.StatusPermanentRedirect ||
		resp.Header.Get("Location") != want {
		t.Fatalf("got %d Location %q, want 308 %q", resp.StatusCode, resp.Header.Get("Location"), want)
	}
}

func TestBrowserOnUnknownHostGetsErrorPageButRawClientsGetAlert(t *testing.T) {
	env := startRelay(t, 1)
	expectErrorPage(t, httpsClient(t, env, false), tunnelURL(env, "nobody", "/"), http.StatusNotFound, "tunnel-not-found")
	if _, err := connect(t, env, "nobody."+baseDomain, []byte("x")); err == nil {
		t.Fatal("mode B connect to an unknown host succeeded")
	}
}
