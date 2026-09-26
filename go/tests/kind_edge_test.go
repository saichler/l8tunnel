package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/types/l8api"
	"github.com/saichler/l8types/go/types/l8notify"
)

func mustJSON(t *testing.T, v interface{}) string {
	t.Helper()
	data, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(data)
}

// siteCert is a self-signed certificate and key for names, as PEM.
func siteCert(t *testing.T, names ...string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(1, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
}

// upload stores a file in FileStore, as the UI's certificate upload does.
func upload(t *testing.T, c *kindClient, name string, data []byte) *l8api.L8FileUploadResponse {
	t.Helper()
	out := &l8api.L8FileUploadResponse{}
	c.mustDo(http.MethodPost, common.FileStoreArea, common.FileStoreService, &l8api.L8FileUploadRequest{
		FileName: name, MimeType: "application/x-pem-file", FileData: data, DocumentId: common.CertDocumentID, Version: 1}, out)
	return out
}

func domainsNamed(t *testing.T, c *kindClient, domain string) []*tun.EdgeDomain {
	t.Helper()
	list := &tun.EdgeDomainList{}
	if err := c.query(common.AreaEdge, common.DomainService, "select * from EdgeDomain where domain="+domain, list); err != nil {
		t.Fatal(err)
	}
	return list.List
}

func TestKindEdgeDomains(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	const base = "tunnel.kind.test" // k8s/l8tunnel-kind.yaml

	// The backend creates the built-in tunnel base domain.
	var bases []*tun.EdgeDomain
	waitUntil(t, 60*time.Second, "tunnel base domain", func() bool {
		bases = domainsNamed(t, c, base)
		return len(bases) == 1
	})
	tb := bases[0]
	if tb.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE || len(tb.PortForwards) != 4 || tb.PortForwards[0].TargetPort != 8443 {
		t.Fatalf("tunnel base domain %+v", tb)
	}
	// Its port forwards follow cluster.yaml, whatever a client sends.
	tb.PortForwards = tb.PortForwards[:1]
	c.mustDo(put, common.AreaEdge, common.DomainService, tb, nil)
	if got := domainsNamed(t, c, base); len(got[0].PortForwards) != 4 {
		t.Fatalf("tunnel base forwards changed: %+v", got[0].PortForwards)
	}

	domain := uniqueName("shop") + ".example.test"
	certPEM, keyPEM := siteCert(t, domain, "www."+domain)
	certFile := upload(t, c, domain+".crt", certPEM)
	keyFile := upload(t, c, domain+".key", keyPEM)
	forward := &tun.EdgePortForward{ListenPort: 443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS,
		Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
		Targets: []string{"10.0.0.10:2443", "10.0.0.11:2443*2"}, BackendScheme: tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTPS,
		Lb: tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN, Enabled: true}
	site := &tun.EdgeDomain{Domain: domain, Aliases: []string{"www." + domain}, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE,
		Enabled: true, PortForwards: []*tun.EdgePortForward{forward}}

	// Terminate needs a certificate.
	c.expectRefused("terminate without certificate", "certificate", post, common.AreaEdge, common.DomainService, site)

	site.CertStoragePath, site.CertFileName = certFile.StoragePath, certFile.FileName
	site.KeyStoragePath, site.KeyFileName = keyFile.StoragePath, keyFile.FileName
	// Clients can't set the summary; the service computes it.
	site.CertStatus = tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRED
	c.mustDo(post, common.AreaEdge, common.DomainService, site, nil)
	got := domainsNamed(t, c, domain)
	if len(got) != 1 || got[0].CertStatus != tun.EdgeCertStatus_EDGE_CERT_STATUS_VALID || got[0].CertSubject != domain ||
		len(got[0].CertSans) != 2 || got[0].ConfigVersion == 0 {
		t.Fatalf("stored domain %+v", got)
	}
	stored := got[0]
	t.Cleanup(func() {
		c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+stored.DomainId)
	})

	// A certificate that doesn't cover the names is refused.
	otherCert, otherKey := siteCert(t, "elsewhere.example.test")
	mismatch := &tun.EdgeDomain{Domain: uniqueName("m") + ".example.test", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE,
		CertStoragePath: upload(t, c, "o.crt", otherCert).StoragePath, KeyStoragePath: upload(t, c, "o.key", otherKey).StoragePath}
	c.expectRefused("certificate for another name", "doesn't cover", post, common.AreaEdge, common.DomainService, mismatch)
	// A path outside the certificate folder is refused.
	c.expectRefused("foreign storage path", "isn't an uploaded certificate", post, common.AreaEdge, common.DomainService,
		&tun.EdgeDomain{Domain: uniqueName("p") + ".example.test", CertStoragePath: "/data/l8files/general/1/x", KeyStoragePath: keyFile.StoragePath})
	// A TCP port in the relays' range is taken.
	c.expectRefused("port in the relay range", "TCP", post, common.AreaEdge, common.DomainService, &tun.EdgeDomain{
		Domain: uniqueName("db") + ".example.test", PortForwards: []*tun.EdgePortForward{{ListenPort: 22500,
			Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP, Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH,
			TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL, TargetPort: 5432}}})
	// Sites share 443 by SNI, but not a TCP port.
	shared := &tun.EdgeDomain{Domain: uniqueName("raw") + ".example.test", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{{ListenPort: 443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
			Targets: []string{"10.0.0.12:443"}, Enabled: true}, {ListenPort: 6001, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
			TargetPort: 5432, Enabled: true}}}
	c.mustDo(post, common.AreaEdge, common.DomainService, shared, nil)
	sharedRow := domainsNamed(t, c, shared.Domain)[0]
	t.Cleanup(func() {
		c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+sharedRow.DomainId)
	})
	tcpOn := func(port int32, protocol tun.EdgeProtocol) *tun.EdgeDomain {
		return &tun.EdgeDomain{Domain: uniqueName("clash") + ".example.test", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
			PortForwards: []*tun.EdgePortForward{{ListenPort: port, Protocol: protocol, Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH,
				TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL, TargetPort: 5432, Enabled: true}}}
	}
	c.expectRefused("a TCP port another site uses", "can't be shared", post, common.AreaEdge, common.DomainService,
		tcpOn(6001, tun.EdgeProtocol_EDGE_PROTOCOL_TCP))
	c.expectRefused("TCP on a TLS port", "is TLS on domain", post, common.AreaEdge, common.DomainService,
		tcpOn(443, tun.EdgeProtocol_EDGE_PROTOCOL_TCP))

	// A wildcard site name under the base domain would cover tunnels.
	c.expectRefused("wildcard under base", "cover tunnel names", post, common.AreaEdge, common.DomainService,
		&tun.EdgeDomain{Domain: "x." + base, Aliases: []string{"*.apps." + base}})

	// A site name under the base domain blocks that tunnel name.
	admin := &tun.EdgeDomain{Domain: uniqueName("ui") + "." + base, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true}
	c.mustDo(post, common.AreaEdge, common.DomainService, admin, nil)
	adminRow := domainsNamed(t, c, admin.Domain)[0]
	t.Cleanup(func() {
		c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+adminRow.DomainId)
	})
	tok := issueToken(t, c, uniqueName("ke"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	label := admin.Domain[:len(admin.Domain)-len(base)-1]
	c.expectRefused("reserving a site's name", "edge domain", post, common.AreaAccess, common.ReservationService,
		&tun.TunReservation{Name: label, TokenId: tok.TokenId})
}

func TestKindAlertRulesAndEdgeNodes(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	target := []*l8notify.NotifyTarget{{Channel: l8notify.NotifyChannel_NOTIFY_CHANNEL_EMAIL, Endpoint: "ops@example.test"}}
	rule := &tun.TunAlertRule{Name: uniqueName("cert"), Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING,
		Threshold: 30, Targets: target, Enabled: true}
	c.mustDo(post, common.AreaAlerts, common.AlertService, rule, nil)
	rules := &tun.TunAlertRuleList{}
	if err := c.query(common.AreaAlerts, common.AlertService, "select * from TunAlertRule where name="+rule.Name, rules); err != nil {
		t.Fatal(err)
	}
	if len(rules.List) != 1 || rules.List[0].CooldownMinutes != 60 {
		t.Fatalf("stored rule %+v", rules.List)
	}
	if err := c.remove(common.AreaAlerts, common.AlertService, "TunAlertRule", "ruleId="+rules.List[0].RuleId); err != nil {
		t.Fatal(err)
	}
	c.expectRefused("no targets", "target", post, common.AreaAlerts, common.AlertService,
		&tun.TunAlertRule{Name: "x", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST})
	c.expectRefused("no threshold", "threshold", post, common.AreaAlerts, common.AlertService,
		&tun.TunAlertRule{Name: "x", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING, Targets: target})

	// KIND sets L8TUNNEL_ALLOW_SIMULATED, so a simulated report is kept.
	id := uniqueName("edge-sim")
	c.mustDo(post, common.AreaEdge, common.EdgeNodeService, &tun.EdgeNode{EdgeId: id, NodeIp: "10.9.9.9", Simulated: true}, nil)
	nodes := &tun.EdgeNodeList{}
	if err := c.query(common.AreaEdge, common.EdgeNodeService, "select * from EdgeNode where edgeId="+id, nodes); err != nil {
		t.Fatal(err)
	}
	if len(nodes.List) != 1 || nodes.List[0].LastSeen == 0 {
		t.Fatalf("edge node %+v", nodes.List)
	}
	if err := c.remove(common.AreaEdge, common.EdgeNodeService, "EdgeNode", "edgeId="+id); err != nil {
		t.Fatal(err)
	}
}

// TestKindSimplePortForward: the UI's port forward row sets only the
// protocol, the incoming port and the target port. The backend fills the
// rest of a new forward (no ID yet): an ID, passthrough, this node as the
// target, enabled.
func TestKindSimplePortForward(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	domain := uniqueName("simple") + ".kind.site"
	site := &tun.EdgeDomain{Domain: domain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{
			{Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS, ListenPort: 16443, TargetPort: 5443},
			{Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP, ListenPort: 16022, TargetPort: 22},
		}}
	c.mustDo(post, common.AreaEdge, common.DomainService, site, nil)
	got := domainsNamed(t, c, domain)
	if len(got) != 1 {
		t.Fatalf("stored %d domains named %s", len(got), domain)
	}
	t.Cleanup(func() { c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+got[0].DomainId) })
	ids := map[string]bool{}
	for i, f := range got[0].PortForwards {
		if f.ForwardId == "" || ids[f.ForwardId] || f.Mode != tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH ||
			f.TargetKind != tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL || !f.Enabled {
			t.Fatalf("forward %d not defaulted: %+v", i, f)
		}
		ids[f.ForwardId] = true
	}
	// An existing forward keeps what it has: disabling it sticks.
	stored := got[0]
	stored.PortForwards[1].Enabled = false
	c.mustDo(put, common.AreaEdge, common.DomainService, stored, nil)
	if f := domainsNamed(t, c, domain)[0].PortForwards[1]; f.Enabled || f.ForwardId != stored.PortForwards[1].ForwardId {
		t.Fatalf("an existing forward was re-defaulted: %+v", f)
	}
}
