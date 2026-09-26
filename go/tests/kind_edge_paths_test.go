package tests

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/client"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// otherRelay is the NodePort of the relay that doesn't own a tunnel.
func otherRelay(owner string) string {
	if owner == kindRelay0 {
		return kindRelay1TLS
	}
	return kindRelay0TLS
}

// passthroughGet speaks HTTP over TLS to addr with the tunnel's SNI and
// returns the certificate it saw and the body.
func passthroughGet(t *testing.T, addr, host string) ([]byte, string) {
	t.Helper()
	conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: host, InsecureSkipVerify: true})
	if err != nil {
		t.Fatalf("passthrough via %s: %v", addr, err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", host)
	resp, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("passthrough via %s: %v", addr, err)
	}
	body, _ := io.ReadAll(resp.Body)
	return conn.ConnectionState().PeerCertificates[0].Raw, string(body)
}

// Traffic paths through the edge and the non-owner relay: TLS passthrough,
// mode B, the client IP for access lists, and simulated records that must
// never be routed to.
func TestKindEdgePaths(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("paths"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })

	backend := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "end to end") }))
	t.Cleanup(backend.Close)
	pt, box, denied, agentID := uniqueName("pt"), uniqueName("pbox"), uniqueName("deny"), uniqueName("pagent")
	a := waitReady(t, kindAgent(t, ca, kindEdgeHTTPS, tok.Token, agentID,
		agent.TunnelConfig{Name: pt, Type: l8tunnel.TunnelType_TUNNEL_TYPE_TLS, Target: backend.Listener.Addr().String()},
		agent.TunnelConfig{Name: box, Type: sshType, Target: startEchoServer(t)},
		agent.TunnelConfig{Name: denied, Type: httpType, Target: startInspectServer(t), AllowIPs: []string{"192.0.2.1"}}))
	var owner, clientIP string
	waitUntil(t, 20*time.Second, "live records", func() bool {
		r, ag := liveTunnel(t, c, pt), liveAgent(t, c, agentID)
		if r == nil || ag == nil {
			return false
		}
		owner, clientIP = r.RelayId, ag.PublicIp
		return true
	})

	t.Run("TLS passthrough through the edge and the other relay", func(t *testing.T) {
		host := pt + "." + kindBase
		for _, addr := range []string{kindEdgeHTTPS, otherRelay(owner)} {
			cert, body := passthroughGet(t, addr, host)
			if !bytes.Equal(cert, backend.Certificate().Raw) || body != "end to end" {
				t.Fatalf("via %s: body %q, backend certificate %v", addr, body, bytes.Equal(cert, backend.Certificate().Raw))
			}
		}
	})

	t.Run("mode B through the edge", func(t *testing.T) {
		var out bytes.Buffer
		err := client.Connect(t.Context(), client.Config{Host: box + "." + kindBase, RelayAddr: kindEdgeHTTPS,
			CAFile: ca.caFile, Proxy: "none"}, strings.NewReader("via the edge"), &out)
		if err != nil || out.String() != "via the edge" {
			t.Fatalf("mode B through the edge: %q %v", out.String(), err)
		}
	})

	t.Run("access lists see the client IP through the edge", func(t *testing.T) {
		resp, err := relayHTTPSClient(t, ca, kindEdgeHTTPS).Get("https://" + denied + "." + kindBase + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("a client outside the allow list: status %d", resp.StatusCode)
		}
		// The same client allowed by its own address.
		allowed := uniqueName("allow")
		waitReady(t, kindAgent(t, ca, kindEdgeHTTPS, tok.Token, uniqueName("aagent"),
			agent.TunnelConfig{Name: allowed, Type: httpType, Target: startInspectServer(t), AllowIPs: []string{clientIP}}))
		if seen := getSeen(t, relayHTTPSClient(t, ca, kindEdgeHTTPS), "https://"+allowed+"."+kindBase+"/ok", nil); seen.URI != "/ok" {
			t.Fatalf("the allowed client %s: %+v", clientIP, seen)
		}
	})

	t.Run("simulated tunnels are never routed to", func(t *testing.T) {
		relayID, name := uniqueName("sim-relay"), uniqueName("simweb")
		announce := func(tunnels ...*tun.TunLiveTunnel) {
			req := &tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE, RelayId: relayID, Tunnels: tunnels,
				Relay: &tun.TunRelay{RelayId: relayID, PodIp: "10.99.0.250", TlsPort: 8443, HttpPort: 8080, StreamPort: 8444,
					State: tun.TunRelayState_TUN_RELAY_STATE_READY, LastSeen: time.Now().Unix(), Simulated: true}}
			resp := &tun.TunClaimResponse{}
			c.mustDo(post, common.AreaLive, common.ClaimService, req, resp)
			if resp.Error != tun.TunClaimError_TUN_CLAIM_ERROR_UNSPECIFIED {
				t.Fatalf("announce: %s %s", resp.Error, resp.Message)
			}
		}
		announce(&tun.TunLiveTunnel{TunnelId: ifs.NewUuid(), Name: name, Type: tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP,
			State: tun.TunLiveState_TUN_LIVE_STATE_ACTIVE, AgentId: "sim-agent", TokenId: tok.TokenId, Simulated: true})
		t.Cleanup(func() { announce() })
		if liveTunnel(t, c, name) == nil {
			t.Fatal("the simulated tunnel isn't listed")
		}
		resp, err := relayHTTPSClient(t, ca, kindEdgeHTTPS).Get("https://" + name + "." + kindBase + "/")
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusNotFound {
			t.Fatalf("a simulated tunnel: status %d (%s), want 404", resp.StatusCode, resp.Header.Get(httpproxy.ErrorHeader))
		}
	})
	stopAgent(t, a)
}
