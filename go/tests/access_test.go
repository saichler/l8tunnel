package tests

import (
	"crypto/tls"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/client"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

func mustClientTLS(t *testing.T, env *relayEnv) *tls.Config {
	t.Helper()
	cfg, err := transport.ClientTLSConfig(controlSNI, env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func storeReservation(name, tokenID string, port int) *store.Reservation {
	return &store.Reservation{Name: name, TokenID: tokenID, Port: port, Created: time.Now()}
}

// refused reports whether a mode A connection is closed without an echo.
func refused(addr string) bool {
	got, err := roundTrip(addr, []byte("ping"))
	return err != nil || string(got) != "ping"
}

func TestIPAllowAndDenyLists(t *testing.T) {
	env := startRelay(t, 3)
	target := startEchoServer(t)
	ra := startAgent(t, env,
		agent.TunnelConfig{Name: "lan-only", Type: tcpType, Target: target, AllowIPs: []string{"10.0.0.0/8"}},
		agent.TunnelConfig{Name: "no-local", Type: tcpType, Target: target, DenyIPs: []string{"127.0.0.1"}},
		agent.TunnelConfig{Name: "local", Type: tcpType, Target: target, AllowIPs: []string{"127.0.0.0/8"}, DenyIPs: []string{"127.0.0.2"}},
	)
	eps := ra.agent.Endpoints()
	if !refused(publicAddr(eps[0].GetPublicPort())) || !refused(publicAddr(eps[1].GetPublicPort())) {
		t.Fatal("a client outside the allow list or inside the deny list got through (mode A)")
	}
	if refused(publicAddr(eps[2].GetPublicPort())) {
		t.Fatal("an allowed client was refused (mode A)")
	}
	// Mode B applies the same lists.
	if _, err := connect(t, env, "no-local."+baseDomain, []byte("x")); err == nil {
		t.Fatal("a denied client got through (mode B)")
	}
	if got, err := connect(t, env, "local."+baseDomain, []byte("ok")); err != nil || string(got) != "ok" {
		t.Fatalf("an allowed client was refused (mode B): %q %v", got, err)
	}
}

func TestHTTPIPDenyGets403(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t), AllowIPs: []string{"10.0.0.0/8"}})
	expectErrorPage(t, httpsClient(t, env, false), tunnelURL(env, "web", "/"), http.StatusForbidden, "ip-denied")
}

func TestHTTPBasicAuth(t *testing.T) {
	env := startRelay(t, 1)
	hash, err := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	// PHP/htpasswd-style $2y$ hashes work too.
	yHash := strings.Replace(string(hash), "$2a$", "$2y$", 1)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "authorization="+r.Header.Get("Authorization"))
	}))
	t.Cleanup(srv.Close)
	startAgent(t, env, agent.TunnelConfig{Name: "admin", Type: httpType, Target: srv.Listener.Addr().String(),
		BasicUsers: []agent.BasicUser{{Username: "alice", BcryptHash: yHash}}})
	client := httpsClient(t, env, false)
	url := tunnelURL(env, "admin", "/")

	expectErrorPage(t, client, url, http.StatusUnauthorized, "unauthorized")
	for _, creds := range [][2]string{{"alice", "wrong"}, {"bob", "s3cret"}} {
		req, _ := http.NewRequest("GET", url, nil)
		req.SetBasicAuth(creds[0], creds[1])
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusUnauthorized || !strings.HasPrefix(resp.Header.Get("WWW-Authenticate"), "Basic") {
			t.Fatalf("%v: got %d, want a 401 challenge", creds, resp.StatusCode)
		}
	}
	for i := 0; i < 2; i++ { // the second request is served from the credential cache
		req, _ := http.NewRequest("GET", url, nil)
		req.SetBasicAuth("alice", "s3cret")
		resp, err := client.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		if resp.StatusCode != http.StatusOK || string(body) != "authorization=" {
			t.Fatalf("got %d %q; want 200 with the Authorization header removed", resp.StatusCode, body)
		}
	}
}

func TestAccessTokenProtectsModeB(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, rateLimits: &relay.RateLimits{AuthFailuresPerMinute: 2}})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "vault", Type: sshType, Target: startEchoServer(t), AccessToken: "open-sesame"})
	ep := ra.agent.Endpoints()[0]
	if ep.GetPublicPort() != 0 {
		t.Fatalf("a tunnel with an access token got public port %d", ep.GetPublicPort())
	}

	withToken := func(token string) ([]byte, error) {
		ctx := t.Context()
		var out strings.Builder
		err := client.Connect(ctx, client.Config{Host: "vault." + baseDomain, RelayAddr: env.addr,
			CAFile: env.pki.caFile, AccessToken: token}, strings.NewReader("secret data"), &out)
		return []byte(out.String()), err
	}
	if got, err := withToken("open-sesame"); err != nil || string(got) != "secret data" {
		t.Fatalf("right token: %q %v", got, err)
	}
	if _, err := withToken(""); err == nil || !strings.Contains(err.Error(), "access-token") {
		t.Fatalf("no token: %v, want a handshake error hinting at --access-token", err)
	}
	for i := 0; i < 2; i++ {
		if _, err := withToken("guess"); err == nil || !strings.Contains(err.Error(), "rejected") {
			t.Fatalf("wrong token: %v, want 'access token rejected'", err)
		}
	}
	// Two failures used up this IP's budget: even the right token is refused now.
	if _, err := withToken("open-sesame"); err == nil {
		t.Fatal("the right token was accepted after the failure limit was reached")
	}
}

func TestAccessPolicyValidation(t *testing.T) {
	env := startRelay(t, 1)
	h, err := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	validHash := string(h)
	bad := map[string]agent.TunnelConfig{
		"basic on tcp":     {Type: tcpType, Target: "h:1", BasicUsers: []agent.BasicUser{{Username: "a", BcryptHash: validHash}}},
		"token on http":    {Type: httpType, Target: "h:1", AccessToken: "x"},
		"token with port":  {Type: tcpType, Target: "h:1", AccessToken: "x", PublicPort: 22001},
		"bad cidr":         {Type: tcpType, Target: "h:1", AllowIPs: []string{"10.0.0.0/33"}},
		"not bcrypt":       {Type: httpType, Target: "h:1", BasicUsers: []agent.BasicUser{{Username: "a", BcryptHash: "plaintext"}}},
		"colon in user":    {Type: httpType, Target: "h:1", BasicUsers: []agent.BasicUser{{Username: "a:b", BcryptHash: validHash}}},
		"deny list typo":   {Type: tcpType, Target: "h:1", DenyIPs: []string{"localhost"}},
		"http public port": {Type: httpType, Target: "h:1", PublicPort: 22001},
	}
	for name, tc := range bad {
		_, err := agent.New(agent.Config{RelayAddr: env.addr, TLS: mustClientTLS(t, env), Token: testToken, Tunnels: []agent.TunnelConfig{tc}})
		if err == nil {
			t.Errorf("%s: agent.New accepted it", name)
		}
	}
	if _, err := auth.HashPassword(""); err == nil {
		t.Error("HashPassword accepted an empty password")
	}
}

func TestConnectionRateLimit(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, rateLimits: &relay.RateLimits{ConnectionsPerSecond: 0.001, ConnectionsBurst: 5}})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "busy", Type: tcpType, Target: startEchoServer(t)})
	addr := publicAddr(ra.agent.Endpoints()[0].GetPublicPort())
	// The agent's own connection used one of the 5.
	ok := 0
	for i := 0; i < 6; i++ {
		if !refused(addr) {
			ok++
		}
	}
	if ok != 4 {
		t.Fatalf("%d of 6 connections got through, want 4", ok)
	}
}

func TestAuthFailureLimitBlocksAgents(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, rateLimits: &relay.RateLimits{AuthFailuresPerMinute: 2}})
	for i := 0; i < 2; i++ {
		err := runAgentExpectError(t, env, "l8t_00000000_wrongwrongwrongwrongwrongwrongwrongwrongwro",
			agent.TunnelConfig{Type: tcpType, Target: unusedAddr(t)})
		expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	}
	// Now even a valid token from this address is turned away for a while.
	ra := runAgent(t, newAgent(t, env, testToken, agent.TunnelConfig{Type: tcpType, Target: unusedAddr(t)}))
	select {
	case <-ra.agent.Ready():
		t.Fatal("an agent registered from an address over its auth failure limit")
	case <-time.After(time.Second):
	}
}
