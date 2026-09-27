package tests

import (
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/edgeconf"
	"github.com/saichler/l8tunnel/go/types/tun"
)

func TestEdgeTargetsValidate(t *testing.T) {
	good := []*tun.EdgeTarget{
		{Host: "192.168.1.120", Port: 2443},
		{Host: "web.lan", Port: 443, Weight: 3},
		{Host: "10.0.0.5", Port: 80, Weight: 2, Disabled: true},
		{Host: "fd00::1", Port: 8443},
		{Host: "probler-web.svc", Port: 13443, Weight: edgeconf.MaxWeight},
	}
	for _, tg := range good {
		if err := edgeconf.CheckTarget(tg); err != nil {
			t.Errorf("CheckTarget(%+v): %v", tg, err)
		}
	}
	if w := edgeconf.Weight(&tun.EdgeTarget{Host: "h", Port: 1}); w != 1 {
		t.Errorf("an unset weight is %d, want 1", w)
	}
	if a := edgeconf.Address(&tun.EdgeTarget{Host: "fd00::1", Port: 8443}); a != "[fd00::1]:8443" {
		t.Errorf("Address = %q", a)
	}
	for _, bad := range []*tun.EdgeTarget{nil, {Port: 443}, {Host: "h"}, {Host: "h", Port: 70000},
		{Host: "h", Port: 1, Weight: -1}, {Host: "h", Port: 1, Weight: edgeconf.MaxWeight + 1}, {Host: "a b", Port: 1}, {Host: "h:1", Port: 1}} {
		if err := edgeconf.CheckTarget(bad); err == nil {
			t.Errorf("CheckTarget(%+v) accepted", bad)
		}
	}
}

func forward(port, end int32, proto tun.EdgeProtocol, mode tun.EdgeForwardMode, targets ...string) *tun.EdgePortForward {
	return &tun.EdgePortForward{ListenPort: port, ListenPortEnd: end, Protocol: proto, Mode: mode,
		TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS, Targets: targetsOf(targets...), Enabled: true}
}

func site(id, domain string, fwds ...*tun.EdgePortForward) *tun.EdgeDomain {
	return &tun.EdgeDomain{DomainId: id, Domain: domain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE,
		Enabled: true, PortForwards: fwds, CertStatus: tun.EdgeCertStatus_EDGE_CERT_STATUS_VALID}
}

func TestEdgeDomainValidation(t *testing.T) {
	const tls, tcp, http = tun.EdgeProtocol_EDGE_PROTOCOL_TLS, tun.EdgeProtocol_EDGE_PROTOCOL_TCP, tun.EdgeProtocol_EDGE_PROTOCOL_HTTP
	const term, pass, relay = tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, tun.EdgeForwardMode_EDGE_FORWARD_MODE_RELAY
	base := &tun.EdgeDomain{DomainId: "base", Domain: baseDomain, Aliases: []string{"*." + baseDomain},
		Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE, PortForwards: []*tun.EdgePortForward{
			{ListenPort: 443, Protocol: tls, Mode: relay, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS, TargetPort: 8443},
			{ListenPort: 22000, ListenPortEnd: 22999, Protocol: tcp, Mode: relay, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS, TargetPort: 8444},
		}}
	probler := site("p", "Probler.Dev", forward(443, 0, tls, term, "192.168.1.120:2443", "192.168.1.121:2443"),
		forward(9092, 0, tls, term, "192.168.1.120:9093"))
	probler.Aliases = []string{"WWW.probler.dev"}
	others := []*tun.EdgeDomain{base, probler}

	// Sharing 443 by SNI with the relays and another site is fine; names are
	// normalized in place.
	if err := edgeconf.ValidateDomain(probler, others, baseDomain); err != nil {
		t.Fatalf("valid domain refused: %v", err)
	}
	if probler.Domain != "probler.dev" || probler.Aliases[0] != "www.probler.dev" {
		t.Fatalf("names not normalized: %s %v", probler.Domain, probler.Aliases)
	}
	erp := site("e", "l8erp.one", forward(443, 0, tls, term, "192.168.1.120:2773"))
	if err := edgeconf.ValidateDomain(erp, others, baseDomain); err != nil {
		t.Fatalf("a second site on 443 refused: %v", err)
	}

	bad := map[string]*tun.EdgeDomain{
		"name of another domain":      site("x", "www.probler.dev", forward(443, 0, tls, pass, "h:1")),
		"TCP port in the relay range": site("x", "db.example.com", forward(22050, 0, tcp, pass, "h:5432")),
		"TLS on a TCP port":           site("x", "a.example.com", forward(22000, 0, tls, pass, "h:1")),
		"HTTP on a TLS port":          site("x", "a.example.com", forward(9092, 0, http, pass, "h:1")),
		"terminate without cert": func() *tun.EdgeDomain {
			d := site("x", "a.example.com", forward(8443, 0, tls, term, "h:1"))
			d.CertStatus = tun.EdgeCertStatus_EDGE_CERT_STATUS_MISSING
			return d
		}(),
		"terminate on TCP":     site("x", "a.example.com", forward(7000, 0, tcp, term, "h:1")),
		"relay mode on a site": site("x", "a.example.com", forward(7000, 0, tcp, relay, "h:1")),
		"no enabled target":    site("x", "a.example.com", forward(7000, 0, tcp, pass, "!h:1")),
		"bad target": site("x", "a.example.com", &tun.EdgePortForward{ListenPort: 7000, Protocol: tcp, Mode: pass,
			TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS, Targets: []*tun.EdgeTarget{{Host: "nohost"}}, Enabled: true}),
		"target twice":       site("x", "a.example.com", forward(7000, 0, tcp, pass, "h:1", "h:1*2")),
		"same port twice":    site("x", "a.example.com", forward(7000, 0, tcp, pass, "h:1"), forward(7000, 0, tcp, pass, "h:2")),
		"TLS range":          site("x", "a.example.com", forward(7000, 7010, tls, pass, "h:1")),
		"wildcard domain":    site("x", "*.example.com", forward(7000, 0, tcp, pass, "h:1")),
		"bad IP list":        func() *tun.EdgeDomain { d := site("x", "a.example.com"); d.AllowIps = []string{"lan"}; return d }(),
		"second tunnel base": func() *tun.EdgeDomain { d := site("x", baseDomain); d.Kind = base.Kind; return d }(),
	}
	for name, d := range bad {
		if err := edgeconf.ValidateDomain(d, others, baseDomain); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	// A domain's previous version (same ID) doesn't conflict with itself.
	again := site("p", "probler.dev", forward(9092, 0, tls, term, "192.168.1.120:9093"))
	if err := edgeconf.ValidateDomain(again, others, baseDomain); err != nil {
		t.Fatalf("an update conflicted with its own previous version: %v", err)
	}
}

func TestEdgeCertSummary(t *testing.T) {
	pki := newPKI(t)
	certPEM, err := os.ReadFile(pki.certFile)
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, err := os.ReadFile(pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	s, err := edgeconf.SummarizeCert(certPEM, keyPEM, []string{"app.custom.test", "x." + baseDomain, "*." + baseDomain}, now)
	if err != nil {
		t.Fatal(err)
	}
	// The test certificate expires within a day, so it is EXPIRING.
	if s.Status != tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRING || s.Subject != controlSNI || len(s.Fingerprint) != 64 {
		t.Fatalf("summary %+v", s)
	}
	for _, names := range [][]string{{"other.test"}, {"*.custom.test"}} {
		s, err := edgeconf.SummarizeCert(certPEM, keyPEM, names, now)
		if err != nil || s.Status != tun.EdgeCertStatus_EDGE_CERT_STATUS_MISMATCH || !strings.Contains(s.Problem, names[0]) {
			t.Errorf("names %v: %+v %v", names, s, err)
		}
	}
	if s, _ := edgeconf.SummarizeCert(certPEM, keyPEM, nil, now.Add(48*time.Hour)); s.Status != tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRED {
		t.Errorf("expired certificate status %s", s.Status)
	}
	otherKey, err := os.ReadFile(newPKI(t).keyFile)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := edgeconf.SummarizeCert(certPEM, otherKey, nil, now); err == nil {
		t.Error("a key that doesn't belong to the certificate was accepted")
	}
}
