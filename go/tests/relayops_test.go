package tests

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

func TestReservedNamesCantBeTunnels(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, reserved: []string{"www"}})
	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "www", Type: httpType, Target: startInspectServer(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)
	rec, _ := env.store.TokenByName("test")
	if err := env.srv.Reserve("www", rec.ID, 0); err == nil {
		t.Fatal("an operator reservation took a reserved name")
	}
	startAgent(t, env, agent.TunnelConfig{Name: "web", Type: httpType, Target: startInspectServer(t)})

	if _, err := relay.New(relay.Config{ControlAddr: ":0", TLS: mustServerTLS(t), Tokens: env.store, BaseDomain: baseDomain,
		TCPPortMin: 1000, TCPPortMax: 1001, ReservedNames: []string{"Not A Label"}}); err == nil {
		t.Fatal("an invalid reserved name was accepted")
	}
}

// writeCert writes a self-signed certificate for *.tunnel.test expiring at
// notAfter and returns the cert and key paths.
func writeCert(t *testing.T, notAfter time.Time) (string, string) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: baseDomain},
		DNSNames: []string{"*." + baseDomain}, NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(key)
	dir := t.TempDir()
	certFile, keyFile := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o600)
	os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600)
	return certFile, keyFile
}

func TestStaticCertificateExpiry(t *testing.T) {
	certFile, keyFile := writeCert(t, time.Now().Add(-time.Hour))
	if _, err := certs.New(t.Context(), certs.Config{Mode: certs.ModeStatic, CertFile: certFile, KeyFile: keyFile}); err == nil ||
		!strings.Contains(err.Error(), "expired") {
		t.Fatalf("expired certificate: %v", err)
	}

	logs := &syncBuffer{}
	certFile, keyFile = writeCert(t, time.Now().Add(5*24*time.Hour))
	if _, err := certs.New(t.Context(), certs.Config{Mode: certs.ModeStatic, CertFile: certFile, KeyFile: keyFile,
		Logger: slog.New(slog.NewTextHandler(logs, nil))}); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 2*time.Second, "expiry warning", func() bool { return strings.Contains(logs.String(), "expires soon") })
	if !strings.Contains(logs.String(), "days_left=4") && !strings.Contains(logs.String(), "days_left=5") {
		t.Fatalf("warning without days left: %s", logs.String())
	}

	quiet := &syncBuffer{}
	certFile, keyFile = writeCert(t, time.Now().Add(60*24*time.Hour))
	certs.New(t.Context(), certs.Config{Mode: certs.ModeStatic, CertFile: certFile, KeyFile: keyFile,
		Logger: slog.New(slog.NewTextHandler(quiet, nil))})
	time.Sleep(100 * time.Millisecond)
	if quiet.String() != "" {
		t.Fatalf("warned about a certificate valid for 60 days: %s", quiet.String())
	}
}

func mustServerTLS(t *testing.T) *tls.Config {
	t.Helper()
	pki := newPKI(t)
	cfg, err := transport.ServerTLSConfig(pki.certFile, pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}
