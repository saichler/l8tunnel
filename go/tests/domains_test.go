package tests

import (
	"bytes"
	"crypto/tls"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var domainPolicy = auth.Policy{Domains: []string{"app.custom.test", "*.shop.test", "*.nocert.test", "pt.passthrough.test"}}

func TestHTTPTunnelOnCustomDomain(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, testPolicy: domainPolicy})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t),
		Domains: []string{"App.Custom.Test.", "store.shop.test"}})
	if got := ra.agent.Endpoints()[0].GetDomains(); len(got) != 2 || got[0] != "app.custom.test" {
		t.Fatalf("endpoint domains %v", got)
	}
	client := httpsClient(t, env, false)
	_, port, _ := net.SplitHostPort(env.addr)
	for _, host := range []string{"app.custom.test", "store.shop.test", "web." + baseDomain} {
		seen := getSeen(t, client, "https://"+host+":"+port+"/x", nil)
		if !strings.HasPrefix(seen.Host, host) {
			t.Fatalf("%s: backend saw Host %q", host, seen.Host)
		}
	}
	// Same tunnel, different names: Host and SNI may differ.
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "app.custom.test"
	getSeen(t, client, "https://store.shop.test:"+port+"/", nil)
}

func TestCustomDomainOfAnotherTunnelIsMisdirected(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, testPolicy: domainPolicy})
	startAgent(t, env,
		agent.TunnelConfig{Name: "a", Type: httpType, Target: startInspectServer(t), Domains: []string{"app.custom.test"}},
		agent.TunnelConfig{Name: "b", Type: httpType, Target: startInspectServer(t)})
	client := httpsClient(t, env, false)
	client.Transport.(*http.Transport).TLSClientConfig.ServerName = "app.custom.test"
	expectErrorPage(t, client, tunnelURL(env, "b", "/"), http.StatusMisdirectedRequest, "misdirected")
}

func TestCustomDomainPolicyAndConflicts(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, testPolicy: domainPolicy})
	target := startInspectServer(t)
	cases := map[string]struct {
		token  string
		tunnel agent.TunnelConfig
		code   l8tunnel.ErrorCode
	}{
		"not in policy":    {testToken, agent.TunnelConfig{Type: httpType, Target: target, Domains: []string{"evil.example.com"}}, forbidden},
		"no domain policy": {otherToken, agent.TunnelConfig{Type: httpType, Target: target, Domains: []string{"app.custom.test"}}, forbidden},
		"under base":       {testToken, agent.TunnelConfig{Type: httpType, Target: target, Domains: []string{"x." + baseDomain}}, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST},
		"no certificate":   {testToken, agent.TunnelConfig{Type: httpType, Target: target, Domains: []string{"a.nocert.test"}}, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			expectRemoteCode(t, runAgentExpectError(t, env, c.token, c.tunnel), c.code)
		})
	}

	startAgent(t, env, agent.TunnelConfig{Name: "first", Type: httpType, Target: target, Domains: []string{"app.custom.test"}})
	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "second", Type: httpType, Target: target, Domains: []string{"app.custom.test"}})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)
	// The failed registration released "second" again.
	startAgent(t, env, agent.TunnelConfig{Name: "second", Type: httpType, Target: target})
}

func TestCustomDomainParkedAndReleased(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, testPolicy: domainPolicy, grace: 200 * time.Millisecond})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t), Domains: []string{"app.custom.test"}})
	stopAgent(t, ra)
	client := httpsClient(t, env, false)
	_, port, _ := net.SplitHostPort(env.addr)
	expectErrorPage(t, client, "https://app.custom.test:"+port+"/", http.StatusBadGateway, "agent-offline")
	time.Sleep(500 * time.Millisecond)
	// After the grace period the domain is no longer served at all: a new
	// connection is refused at the TLS handshake.
	client.Transport.(*http.Transport).CloseIdleConnections()
	if _, err := client.Get("https://app.custom.test:" + port + "/"); err == nil {
		t.Fatal("an expired custom domain is still served")
	}
}

func TestTLSPassthroughOnCustomDomain(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, testPolicy: domainPolicy})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "own cert") }))
	t.Cleanup(srv.Close)
	// The relay's certificate doesn't cover pt.passthrough.test; passthrough
	// doesn't need it to.
	startAgent(t, env, agent.TunnelConfig{Name: "pt", Type: l8tunnel.TunnelType_TUNNEL_TYPE_TLS,
		Target: srv.Listener.Addr().String(), Domains: []string{"pt.passthrough.test"}})
	conn, err := tls.Dial("tcp", env.addr, &tls.Config{ServerName: "pt.passthrough.test", InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !bytes.Equal(conn.ConnectionState().PeerCertificates[0].Raw, srv.Certificate().Raw) {
		t.Fatal("custom-domain passthrough presented a certificate other than the backend's")
	}
}

func TestDomainValidationAndConfig(t *testing.T) {
	env := startRelay(t, 1)
	for name, tc := range map[string]agent.TunnelConfig{
		"tcp with domain": {Type: tcpType, Target: "h:1", Domains: []string{"a.example.com"}},
		"wildcard":        {Type: httpType, Target: "h:1", Domains: []string{"*.example.com"}},
		"single label":    {Type: httpType, Target: "h:1", Domains: []string{"localhost"}},
	} {
		if _, err := agent.New(agent.Config{RelayAddr: env.addr, TLS: mustClientTLS(t, env), Token: testToken, Tunnels: []agent.TunnelConfig{tc}}); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	if _, err := auth.NewTokenRecord("t", testToken, auth.Policy{Domains: []string{"*.Example.com"}}, 4); err == nil {
		t.Error("an uppercase domain pattern was accepted")
	}
	socket := startAdmin(t, env)
	mustAdmin(t, socket, "token", "create", "--name", "shop", "--domains", "*.shop.test,app.custom.test")
	if out := mustAdmin(t, socket, "token", "list"); !strings.Contains(out, "domains=*.shop.test,app.custom.test") {
		t.Fatalf("token list:\n%s", out)
	}
}
