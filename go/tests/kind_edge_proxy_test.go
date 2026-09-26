package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/types/tun"
	"golang.org/x/crypto/ssh"
)

// The edge's public ports as mapped to the host by k8s/kind-start.sh.
const (
	kindEdgeHTTPS = "localhost:18443"
	kindEdgeHTTP  = "localhost:18080"
	kindEdgeGw    = "localhost:12222"
	kindEdgeSite  = "localhost:16000" // edge port 6000
)

func edgeNode(t *testing.T, c *kindClient) *tun.EdgeNode {
	t.Helper()
	list := &tun.EdgeNodeList{}
	if err := c.query(common.AreaEdge, common.EdgeNodeService, "select * from EdgeNode", list); err != nil {
		t.Fatal(err)
	}
	for _, n := range list.List {
		if !n.Simulated {
			return n
		}
	}
	return nil
}

func TestKindEdgeProxy(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("k3"), &tun.TunTokenPolicy{Ports: "22000-22009"})
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })

	boxName, webName := uniqueName("ebox"), uniqueName("eweb")
	a := waitReady(t, kindAgent(t, ca, kindEdgeHTTPS, tok.Token, uniqueName("eagent"),
		agent.TunnelConfig{Name: boxName, Type: sshType, Target: startEchoServer(t)},
		agent.TunnelConfig{Name: webName, Type: httpType, Target: startInspectServer(t)}))
	port := a.agent.Endpoints()[0].GetPublicPort()

	t.Run("agent, HTTP and port 80 through the edge", func(t *testing.T) {
		seen := getSeen(t, relayHTTPSClient(t, ca, kindEdgeHTTPS), "https://"+webName+"."+kindBase+"/e", nil)
		if seen.URI != "/e" || seen.XFF == "" {
			t.Fatalf("HTTP through the edge: %+v", seen)
		}
		req, _ := http.NewRequest("GET", "http://"+kindEdgeHTTP+"/x", nil)
		req.Host = webName + "." + kindBase
		resp, err := (&http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		}}).Do(req)
		if err != nil {
			t.Fatal(err)
		}
		resp.Body.Close()
		if resp.StatusCode != http.StatusPermanentRedirect || !strings.HasPrefix(resp.Header.Get("Location"), "https://"+webName) {
			t.Fatalf("port 80: %d %s", resp.StatusCode, resp.Header.Get("Location"))
		}
	})

	t.Run("mode A through the edge", func(t *testing.T) {
		if port < 22000 || port > 22009 {
			t.Fatalf("port %d isn't mapped to the host", port)
		}
		got, err := roundTrip(localAddr(int(port)), []byte("mode A"))
		if err != nil || string(got) != "mode A" {
			t.Fatalf("mode A through the edge: %q %v", got, err)
		}
	})

	t.Run("SSH gateway through the edge", func(t *testing.T) {
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, _ := ssh.NewSignerFromKey(priv)
		c.mustDo(post, common.AreaAccess, common.GatewayKeyService, &tun.TunGatewayKey{Name: uniqueName("egw"),
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey()))), Tunnels: []string{boxName}}, nil)
		var conn *ssh.Client
		waitUntil(t, 30*time.Second, "gateway login through the edge", func() bool {
			var err error
			conn, err = ssh.Dial("tcp", kindEdgeGw, &ssh.ClientConfig{User: "gw", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			return err == nil
		})
		defer conn.Close()
		ch, err := conn.Dial("tcp", boxName+":22")
		if err != nil {
			t.Fatal(err)
		}
		if !echoes(ch, "gateway via edge") {
			t.Fatal("no echo through the gateway")
		}
	})

	t.Run("sites: terminate and passthrough", func(t *testing.T) {
		site := uniqueName("admin") + ".kind.site"
		siteCA := newKindCANames(t, site)
		// TERMINATE on 443 in front of the web UI (https, self-signed).
		terminate := &tun.EdgePortForward{ForwardId: "https", ListenPort: 443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
			TargetPort: 5443, BackendScheme: tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTPS, SkipVerify: true,
			HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_TCP, Enabled: true}
		// PASSTHROUGH on port 6000 straight to the web UI's TLS.
		passthrough := &tun.EdgePortForward{ForwardId: "raw", ListenPort: 6000, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
			TargetPort: 5443, Enabled: true}
		d := &tun.EdgeDomain{Domain: site, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
			CertStoragePath: upload(t, c, site+".crt", siteCA.certPEM).StoragePath,
			KeyStoragePath:  upload(t, c, site+".key", siteCA.keyPEM).StoragePath,
			PortForwards:    []*tun.EdgePortForward{terminate, passthrough}}
		c.mustDo(post, common.AreaEdge, common.DomainService, d, nil)
		stored := domainsNamed(t, c, site)[0]
		t.Cleanup(func() { c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+stored.DomainId) })

		var body string
		waitUntil(t, 60*time.Second, "terminated site served", func() bool {
			resp, err := relayHTTPSClient(t, siteCA, kindEdgeHTTPS).Get("https://" + site + "/index.html")
			if err != nil {
				return false
			}
			defer resp.Body.Close()
			b := make([]byte, 4096)
			n, _ := resp.Body.Read(b)
			body = string(b[:n])
			return resp.StatusCode == http.StatusOK
		})
		if !strings.Contains(body, "l8tunnel") {
			t.Fatalf("terminated site body: %q", body)
		}
		conn, err := tls.Dial("tcp", kindEdgeSite, &tls.Config{InsecureSkipVerify: true})
		if err != nil {
			t.Fatalf("passthrough site: %v", err)
		}
		conn.Close()
	})

	t.Run("edge report and a port that can't bind", func(t *testing.T) {
		// Port 5443 is taken on the node (the web UI uses the host network).
		d := &tun.EdgeDomain{Domain: uniqueName("busy") + ".kind.site", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
			PortForwards: []*tun.EdgePortForward{{ForwardId: "busy", ListenPort: 5443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
				TargetPort: 1, Enabled: true}}}
		c.mustDo(post, common.AreaEdge, common.DomainService, d, nil)
		stored := domainsNamed(t, c, d.Domain)[0]
		t.Cleanup(func() { c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+stored.DomainId) })
		waitUntil(t, 60*time.Second, "edge report", func() bool {
			n := edgeNode(t, c)
			if n == nil || n.ConfigVersion < stored.ConfigVersion {
				return false
			}
			var https, busy bool
			for _, l := range n.Listeners {
				https = https || (l.Port == 443 && l.Bound)
				busy = busy || (l.Port == 5443 && !l.Bound && l.Error != "")
			}
			return https && busy
		})
	})
}
