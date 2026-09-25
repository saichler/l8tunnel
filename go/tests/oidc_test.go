package tests

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/tunnel/oidc"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// mockIdP is a minimal OIDC provider: discovery, JWKS, an authorize
// endpoint that approves immediately as the configured user, and a token
// endpoint that checks PKCE and returns an RS256 ID token.
type mockIdP struct {
	srv        *httptest.Server
	key        *rsa.PrivateKey
	email      atomic.Value // string
	verified   atomic.Bool
	authorizes atomic.Int32
	mu         sync.Mutex
	codes      map[string]mockGrant
}

type mockGrant struct{ nonce, challenge, email string }

const (
	idpClientID     = "l8tunnel-test"
	idpClientSecret = "test-secret"
)

func startMockIdP(t *testing.T, email string) *mockIdP {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	m := &mockIdP{key: key, codes: map[string]mockGrant{}}
	m.email.Store(email)
	m.verified.Store(true)
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		iss := m.srv.URL
		json.NewEncoder(w).Encode(map[string]interface{}{
			"issuer": iss, "authorization_endpoint": iss + "/authorize", "token_endpoint": iss + "/token",
			"jwks_uri": iss + "/jwks", "id_token_signing_alg_values_supported": []string{"RS256"},
			"response_types_supported": []string{"code"}, "subject_types_supported": []string{"public"},
		})
	})
	mux.HandleFunc("GET /jwks", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]interface{}{"keys": []map[string]string{{
			"kty": "RSA", "kid": "k1", "alg": "RS256", "use": "sig",
			"n": b64(m.key.N.Bytes()), "e": b64(big.NewInt(int64(m.key.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("GET /authorize", func(w http.ResponseWriter, r *http.Request) {
		m.authorizes.Add(1)
		q := r.URL.Query()
		if q.Get("client_id") != idpClientID || q.Get("code_challenge_method") != "S256" {
			http.Error(w, "bad authorize request", http.StatusBadRequest)
			return
		}
		code := randomHex(8)
		m.mu.Lock()
		m.codes[code] = mockGrant{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), email: m.email.Load().(string)}
		m.mu.Unlock()
		http.Redirect(w, r, q.Get("redirect_uri")+"?code="+code+"&state="+url.QueryEscape(q.Get("state")), http.StatusFound)
	})
	mux.HandleFunc("POST /token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		id, secret, ok := r.BasicAuth()
		if !ok {
			id, secret = r.Form.Get("client_id"), r.Form.Get("client_secret")
		}
		m.mu.Lock()
		g, found := m.codes[r.Form.Get("code")]
		delete(m.codes, r.Form.Get("code"))
		m.mu.Unlock()
		sum := sha256.Sum256([]byte(r.Form.Get("code_verifier")))
		if id != idpClientID || secret != idpClientSecret || !found || b64(sum[:]) != g.challenge {
			w.WriteHeader(http.StatusBadRequest)
			json.NewEncoder(w).Encode(map[string]string{"error": "invalid_grant"})
			return
		}
		now := time.Now().Unix()
		idToken := m.sign(map[string]interface{}{
			"iss": m.srv.URL, "sub": "user-1", "aud": idpClientID, "iat": now, "exp": now + 300,
			"nonce": g.nonce, "email": g.email, "email_verified": m.verified.Load(),
		})
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{"access_token": "at", "token_type": "Bearer", "expires_in": 300, "id_token": idToken})
	})
	m.srv = httptest.NewServer(mux)
	t.Cleanup(m.srv.Close)
	return m
}

func (m *mockIdP) sign(claims map[string]interface{}) string {
	header, _ := json.Marshal(map[string]string{"alg": "RS256", "kid": "k1", "typ": "JWT"})
	payload, _ := json.Marshal(claims)
	input := b64(header) + "." + b64(payload)
	sum := sha256.Sum256([]byte(input))
	sig, _ := rsa.SignPKCS1v15(rand.Reader, m.key, crypto.SHA256, sum[:])
	return input + "." + b64(sig)
}

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

func randomHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return b64(b)
}

// newLogin builds the relay's login service for a mock provider.
func newLogin(t *testing.T, idp *mockIdP) *oidc.Service {
	t.Helper()
	key := make([]byte, 32)
	rand.Read(key)
	svc, err := oidc.New(oidc.Config{
		AuthHost:  "auth." + baseDomain,
		Providers: map[string]oidc.ProviderConfig{"mock": {Issuer: idp.srv.URL, ClientID: idpClientID, ClientSecret: idpClientSecret}},
		Key:       key,
		ErrorPage: httpproxy.WriteErrorPage,
		Logger:    testLogger(),
	})
	if err != nil {
		t.Fatal(err)
	}
	return svc
}

// browser is an HTTPS client with a cookie jar that reaches *.tunnel.test
// through the relay and everything else directly.
func browser(t *testing.T, env *relayEnv, follow bool) *http.Client {
	t.Helper()
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 30 * time.Second, Transport: &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool(t, env)},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, _, _ := net.SplitHostPort(addr)
			if strings.HasSuffix(host, "."+baseDomain) {
				addr = env.addr
			}
			var d net.Dialer
			return d.DialContext(ctx, network, addr)
		},
	}}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

func startOIDCTunnel(t *testing.T, idp *mockIdP, rule *agent.OIDCConfig) (*relayEnv, string) {
	t.Helper()
	env := startRelayWith(t, relayOpts{ports: 1, login: newLogin(t, idp)})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		io.WriteString(w, "user="+r.Header.Get(oidc.UserHeader)+" cookie="+r.Header.Get("Cookie"))
	}))
	t.Cleanup(backend.Close)
	startAgent(t, env, agent.TunnelConfig{Name: "app", Type: httpType, Target: backend.Listener.Addr().String(), OIDC: rule})
	return env, tunnelURL(env, "app", "/private?x=1")
}

func TestOIDCLoginFlow(t *testing.T) {
	idp := startMockIdP(t, "alice@example.com")
	env, url := startOIDCTunnel(t, idp, &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"alice@example.com"}})
	client := browser(t, env, true)

	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set(oidc.UserHeader, "mallory@evil.test") // must be replaced
	req.AddCookie(&http.Cookie{Name: "app_pref", Value: "dark"})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || resp.Request.URL.RequestURI() != "/private?x=1" {
		t.Fatalf("after login: %d at %s: %s", resp.StatusCode, resp.Request.URL, body)
	}
	if got := string(body); !strings.HasPrefix(got, "user=alice@example.com ") || strings.Contains(got, "l8tunnel_session") {
		t.Fatalf("backend saw %q; want the verified user and no relay cookie", got)
	}

	// The session cookie is reused: no second trip to the provider.
	resp, err = client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK || idp.authorizes.Load() != 1 {
		t.Fatalf("second request: %d, provider saw %d authorizations (want 1)", resp.StatusCode, idp.authorizes.Load())
	}
}

func TestOIDCRejectsUsersOutsideTheAllowList(t *testing.T) {
	idp := startMockIdP(t, "bob@other.test")
	env, url := startOIDCTunnel(t, idp, &agent.OIDCConfig{Provider: "mock", AllowDomains: []string{"example.com"}})
	resp, err := browser(t, env, true).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden || resp.Header.Get(httpproxy.ErrorHeader) != "not-allowed" {
		t.Fatalf("got %d / %q, want 403 not-allowed", resp.StatusCode, resp.Header.Get(httpproxy.ErrorHeader))
	}

	idp.email.Store("carol@example.com")
	idp.verified.Store(false)
	resp, err = browser(t, env, true).Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("unverified email: got %d, want 403", resp.StatusCode)
	}
}

func TestOIDCNonGetRequestsGet401AndTamperingFails(t *testing.T) {
	idp := startMockIdP(t, "alice@example.com")
	env, url := startOIDCTunnel(t, idp, &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"alice@example.com"}})
	client := browser(t, env, false)

	resp, err := client.Post(url, "text/plain", strings.NewReader("x"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("POST without a session: %d, want 401", resp.StatusCode)
	}

	req, _ := http.NewRequest("GET", url, nil)
	req.AddCookie(&http.Cookie{Name: "l8tunnel_session", Value: "eyJtIjoibWFsbG9yeUBleGFtcGxlLmNvbSJ9.forged"})
	resp, err = client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound || !strings.Contains(resp.Header.Get("Location"), "auth."+baseDomain) {
		t.Fatalf("forged cookie: %d to %q, want a redirect to the login host", resp.StatusCode, resp.Header.Get("Location"))
	}
}

func TestOIDCLoginCodeIsSingleUse(t *testing.T) {
	idp := startMockIdP(t, "alice@example.com")
	env, url := startOIDCTunnel(t, idp, &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"alice@example.com"}})
	client := browser(t, env, true)
	var codeURL string
	client.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Path == oidc.AuthPath && codeURL == "" {
			codeURL = req.URL.String()
		}
		return nil
	}
	resp, err := client.Get(url)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if codeURL == "" {
		t.Fatal("never saw the login code redirect")
	}
	replay, err := browser(t, env, false).Get(codeURL)
	if err != nil {
		t.Fatal(err)
	}
	replay.Body.Close()
	if replay.StatusCode != http.StatusBadRequest || replay.Header.Get(httpproxy.ErrorHeader) != "login-invalid" {
		t.Fatalf("replayed login code: %d / %q, want 400 login-invalid", replay.StatusCode, replay.Header.Get(httpproxy.ErrorHeader))
	}
}

func TestOIDCRegistrationChecks(t *testing.T) {
	idp := startMockIdP(t, "alice@example.com")
	env := startRelayWith(t, relayOpts{ports: 1, login: newLogin(t, idp)})
	target := startInspectServer(t)

	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Type: httpType, Target: target,
		OIDC: &agent.OIDCConfig{Provider: "nope", AllowEmails: []string{"a@b.c"}}})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)
	err = runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "auth", Type: httpType, Target: target})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)

	noLogin := startRelay(t, 1)
	err = runAgentExpectError(t, noLogin, testToken, agent.TunnelConfig{Type: httpType, Target: target,
		OIDC: &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"a@b.c"}}})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)

	for name, tc := range map[string]agent.TunnelConfig{
		"on tcp":        {Type: tcpType, Target: "h:1", OIDC: &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"a@b.c"}}},
		"no allow list": {Type: httpType, Target: "h:1", OIDC: &agent.OIDCConfig{Provider: "mock"}},
		"bad email":     {Type: httpType, Target: "h:1", OIDC: &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"not-an-email"}}},
		"with basic": {Type: httpType, Target: "h:1", OIDC: &agent.OIDCConfig{Provider: "mock", AllowEmails: []string{"a@b.c"}},
			BasicUsers: []agent.BasicUser{{Username: "u", BcryptHash: "$2a$04$" + strings.Repeat("a", 53)}}},
	} {
		if _, err := agent.New(agent.Config{RelayAddr: env.addr, TLS: mustClientTLS(t, env), Token: testToken, Tunnels: []agent.TunnelConfig{tc}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	for name, cfg := range map[string]oidc.Config{
		"http issuer": {AuthHost: "a.b", Providers: map[string]oidc.ProviderConfig{"g": {Issuer: "http://idp.example.com", ClientID: "x", ClientSecret: "y"}}},
		"no secret":   {AuthHost: "a.b", Providers: map[string]oidc.ProviderConfig{"g": {Issuer: "https://idp.example.com", ClientID: "x"}}},
		"short key":   {AuthHost: "a.b", Providers: map[string]oidc.ProviderConfig{"g": {Issuer: "https://idp.example.com", ClientID: "x", ClientSecret: "y"}}, Key: []byte("short")},
	} {
		cfg.ErrorPage = httpproxy.WriteErrorPage
		if _, err := oidc.New(cfg); err == nil {
			t.Errorf("oidc.New %s: accepted", name)
		}
	}
}

func TestOIDCConfigFiles(t *testing.T) {
	t.Setenv("IDP_SECRET", "s3cret")
	pki := newPKI(t)
	f, err := config.LoadServerFile(writeFile(t, "server.yaml", "base_domain: tunnel.test\ntls: {cert: "+pki.certFile+", key: "+pki.keyFile+"}\n"+
		"listen: {https: 127.0.0.1:0, http: \"off\"}\n"+
		"oidc:\n  session_ttl: 1h\n  providers:\n    google: {issuer: https://accounts.google.com, client_id: abc, client_secret: \"${IDP_SECRET}\"}\n"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.NewRelay(t.Context(), testLogger(), newTestStore(t, auth.Policy{}), "test"); err != nil {
		t.Fatal(err)
	}
	f.OIDC.Providers["google"] = struct {
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"`
		Scopes       []string `yaml:"scopes"`
	}{Issuer: "https://accounts.google.com", ClientID: "abc", ClientSecret: "${IDP_UNSET_SECRET}"}
	if _, err := f.NewRelay(t.Context(), testLogger(), newTestStore(t, auth.Policy{}), "test"); err == nil ||
		!strings.Contains(err.Error(), "IDP_UNSET_SECRET") {
		t.Fatalf("unset secret: %v", err)
	}

	af, err := config.LoadAgentFile(writeFile(t, "agent.yaml", "relay: r:443\ntoken: "+testToken+"\ntunnels:\n"+
		"  - {name: app, type: http, target: \"8080\", oidc: {provider: google, allow_domains: [example.com]}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := af.AgentConfig(testLogger(), "test")
	if err != nil || cfg.Tunnels[0].OIDC == nil || cfg.Tunnels[0].OIDC.AllowDomains[0] != "example.com" {
		t.Fatalf("agent oidc config: %+v, %v", cfg.Tunnels[0].OIDC, err)
	}
	cli, err := config.ParseAgentArgs([]string{"--relay", "r:443", "http", "8080", "--oidc", "google",
		"--allow-email", "a@x.com", "--allow-domain", "y.com"}, io.Discard)
	if err != nil || cli.Tunnels[0].OIDC == nil || cli.Tunnels[0].OIDC.AllowEmails[0] != "a@x.com" {
		t.Fatalf("CLI oidc flags: %+v, %v", cli.Tunnels[0].OIDC, err)
	}
}
