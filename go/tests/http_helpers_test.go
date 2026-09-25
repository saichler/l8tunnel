package tests

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/http"
	"os"
	"testing"
	"time"
)

// caPool returns a pool trusting the relay's test CA.
func caPool(t *testing.T, env *relayEnv) *x509.CertPool {
	t.Helper()
	pem, err := os.ReadFile(env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		t.Fatal("no CA certificate")
	}
	return pool
}

// httpsClient returns a client that reaches every host through the relay's
// TLS listener, as if *.tunnel.test resolved to the relay. h2 enables
// HTTP/2; otherwise the client speaks HTTP/1.1.
func httpsClient(t *testing.T, env *relayEnv, h2 bool) *http.Client {
	t.Helper()
	transport := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: caPool(t, env)},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", env.addr)
		},
		ForceAttemptHTTP2: h2,
	}
	t.Cleanup(transport.CloseIdleConnections)
	return &http.Client{
		Transport:     transport,
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// tunnelURL is the public URL of an HTTP tunnel on the test relay.
func tunnelURL(env *relayEnv, name, path string) string {
	_, port, _ := net.SplitHostPort(env.addr)
	return "https://" + name + "." + baseDomain + ":" + port + path
}
