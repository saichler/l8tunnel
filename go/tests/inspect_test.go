package tests

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/inspect"
)

// inspectedTunnel runs an HTTP tunnel "web" to backend with the inspector
// on, and serves the inspector UI on an httptest server.
func inspectedTunnel(t *testing.T, backend http.Handler) (*relayEnv, *httptest.Server) {
	t.Helper()
	env := startRelay(t, 1)
	srv := httptest.NewServer(backend)
	t.Cleanup(srv.Close)
	rec := inspect.NewRecorder(0)
	a := newAgentWith(t, env, func(c *agent.Config) {
		c.Recorder = rec
		c.Tunnels = []agent.TunnelConfig{{Name: "web", Type: httpType, Target: srv.Listener.Addr().String()}}
	})
	waitReady(t, runAgent(t, a))
	ui := httptest.NewServer(rec.Handler(a.DialTarget, true))
	t.Cleanup(ui.Close)
	return env, ui
}

func listEntries(t *testing.T, ui *httptest.Server) []inspect.Summary {
	t.Helper()
	resp, err := http.Get(ui.URL + "/api/requests")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out []inspect.Summary
	json.NewDecoder(resp.Body).Decode(&out)
	return out
}

func getEntry(t *testing.T, ui *httptest.Server, id int64) inspect.Entry {
	t.Helper()
	resp, err := http.Get(fmt.Sprintf("%s/api/requests/%d", ui.URL, id))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var e inspect.Entry
	json.NewDecoder(resp.Body).Decode(&e)
	return e
}

func TestInspectorRecordsRequestsOverKeepAlive(t *testing.T) {
	env, ui := inspectedTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprintf(w, `{"got":%q}`, body)
	}))
	client := httpsClient(t, env, false)
	for i := 0; i < 3; i++ {
		resp, err := client.Post(tunnelURL(env, "web", fmt.Sprintf("/api/items?n=%d", i)), "application/json", strings.NewReader(`{"n":1}`))
		if err != nil {
			t.Fatal(err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	var list []inspect.Summary
	waitUntil(t, 5*time.Second, "3 entries", func() bool { list = listEntries(t, ui); return len(list) == 3 })
	if list[0].URI != "/api/items?n=2" || list[2].URI != "/api/items?n=0" || list[0].Status != 200 {
		t.Fatalf("entries (newest first): %+v", list)
	}
	e := getEntry(t, ui, list[0].ID)
	if e.Method != "POST" || string(e.ReqBody) != `{"n":1}` || string(e.RespBody) != `{"got":"{\"n\":1}"}` ||
		e.ReqHead.Get("X-Forwarded-For") == "" || e.Tunnel != "web" {
		t.Fatalf("entry %+v", e)
	}
}

func TestInspectorKeepsStreamingAndUpgradesWorking(t *testing.T) {
	release := make(chan struct{})
	env, ui := inspectedTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "websocket" {
			conn, rw, _ := w.(http.Hijacker).Hijack()
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n\r\n")
			rw.Flush()
			io.Copy(conn, rw)
			return
		}
		io.WriteString(w, "data: first\n\n")
		w.(http.Flusher).Flush()
		<-release
		io.WriteString(w, "data: second\n\n")
	}))

	resp, err := httpsClient(t, env, false).Get(tunnelURL(env, "web", "/events"))
	if err != nil {
		t.Fatal(err)
	}
	lines := bufio.NewReader(resp.Body)
	if line, err := lines.ReadString('\n'); err != nil || line != "data: first\n" {
		t.Fatalf("streamed first event: %q %v (inspection buffered the response?)", line, err)
	}
	close(release)
	io.ReadAll(lines)
	resp.Body.Close()

	conn, err := tls.Dial("tcp", env.addr, &tls.Config{ServerName: "web." + baseDomain, RootCAs: caPool(t, env), NextProtos: []string{"http/1.1"}})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET /ws HTTP/1.1\r\nHost: web.%s\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n", baseDomain)
	br := bufio.NewReader(conn)
	if r, err := http.ReadResponse(br, nil); err != nil || r.StatusCode != 101 {
		t.Fatalf("upgrade with inspection on: %v %v", r, err)
	}
	conn.Write([]byte("frame"))
	got := make([]byte, 5)
	if _, err := io.ReadFull(br, got); err != nil || string(got) != "frame" {
		t.Fatalf("echo after upgrade: %q %v", got, err)
	}
	waitUntil(t, 5*time.Second, "upgrade entry", func() bool {
		for _, s := range listEntries(t, ui) {
			if s.URI == "/ws" && s.Status == 101 {
				return getEntry(t, ui, s.ID).Upgraded
			}
		}
		return false
	})
}

func TestInspectorTruncatesLargeBodiesButForwardsThemWhole(t *testing.T) {
	env, ui := inspectedTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := sha256.New()
		io.Copy(h, r.Body)
		io.WriteString(w, hex.EncodeToString(h.Sum(nil)))
	}))
	payload := bytes.Repeat([]byte("0123456789abcdef"), 1<<16) // 1 MiB
	sum := sha256.Sum256(payload)
	resp, err := httpsClient(t, env, false).Post(tunnelURL(env, "web", "/upload"), "application/octet-stream", bytes.NewReader(payload))
	if err != nil {
		t.Fatal(err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(got) != hex.EncodeToString(sum[:]) {
		t.Fatal("the backend didn't receive the whole body")
	}
	var list []inspect.Summary
	waitUntil(t, 5*time.Second, "entry", func() bool { list = listEntries(t, ui); return len(list) == 1 })
	e := getEntry(t, ui, list[0].ID)
	if e.ReqSize != int64(len(payload)) || len(e.ReqBody) != inspect.MaxBody {
		t.Fatalf("recorded %d of %d bytes, want %d kept", len(e.ReqBody), e.ReqSize, inspect.MaxBody)
	}
	req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/requests/%d/replay", ui.URL, e.ID), nil)
	req.Header.Set(inspect.ReplayHeader, "1")
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	r.Body.Close()
	if r.StatusCode != http.StatusBadRequest {
		t.Fatalf("replaying a truncated body: %d, want 400", r.StatusCode)
	}
}

func TestInspectorReplayAndSafety(t *testing.T) {
	var hits atomic.Int32
	env, ui := inspectedTunnel(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := hits.Add(1)
		body, _ := io.ReadAll(r.Body)
		fmt.Fprintf(w, "hit %d body=%s", n, body)
	}))
	events, err := http.Get(ui.URL + "/api/events")
	if err != nil {
		t.Fatal(err)
	}
	defer events.Body.Close()
	evLines := bufio.NewReader(events.Body)

	resp, err := httpsClient(t, env, false).Post(tunnelURL(env, "web", "/hook"), "text/plain", strings.NewReader("payload"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	for {
		line, err := evLines.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if strings.HasPrefix(line, "data: ") && strings.Contains(line, `"/hook"`) {
			break // the live event arrived
		}
	}
	id := listEntries(t, ui)[0].ID

	replay := func(host string, withHeader bool) *http.Response {
		req, _ := http.NewRequest("POST", fmt.Sprintf("%s/api/requests/%d/replay", ui.URL, id), nil)
		if host != "" {
			req.Host = host
		}
		if withHeader {
			req.Header.Set(inspect.ReplayHeader, "1")
		}
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		return r
	}
	if r := replay("", false); r.StatusCode != http.StatusForbidden {
		t.Fatalf("replay without the inspector header: %d, want 403", r.StatusCode)
	}
	if r := replay("evil.example.com", true); r.StatusCode != http.StatusForbidden {
		t.Fatalf("replay with a rebinding Host header: %d, want 403", r.StatusCode)
	}
	r := replay("", true)
	var e inspect.Entry
	json.NewDecoder(r.Body).Decode(&e)
	r.Body.Close()
	if r.StatusCode != http.StatusOK || e.ReplayOf != id || string(e.RespBody) != "hit 2 body=payload" || hits.Load() != 2 {
		t.Fatalf("replay: %d %+v (hits %d)", r.StatusCode, e, hits.Load())
	}

	for addr, ok := range map[string]bool{"127.0.0.1:4040": true, "localhost:4040": true, "[::1]:4040": true, "0.0.0.0:4040": false, "192.168.1.5:4040": false} {
		if err := inspect.CheckListenAddr(addr, false); (err == nil) != ok {
			t.Errorf("CheckListenAddr(%s) = %v", addr, err)
		}
	}
	if err := inspect.CheckListenAddr("0.0.0.0:4040", true); err != nil {
		t.Errorf("inspect_public didn't allow 0.0.0.0: %v", err)
	}
	page, err := http.Get(ui.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	html, _ := io.ReadAll(page.Body)
	page.Body.Close()
	if !strings.Contains(string(html), "l8tunnel inspector") || strings.Contains(string(html), ".innerHTML") {
		t.Fatal("the UI page is missing or uses innerHTML")
	}
}
