package certs

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"
)

// Dynamic holds one certificate that can be replaced while the relay runs:
// in Kubernetes the tunnel certificate is uploaded in the management UI,
// and relays pick up a new one without a restart.
type Dynamic struct {
	mu   sync.RWMutex
	cert *tls.Certificate
	leaf *x509.Certificate
}

// ErrNoCertificate: nothing has been loaded yet.
var ErrNoCertificate = errors.New("no certificate loaded yet")

// Set replaces the certificate; the old one stays on error.
func (d *Dynamic) Set(certPEM, keyPEM []byte) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return fmt.Errorf("certificate: %w", err)
	}
	pair.Leaf = leaf
	d.mu.Lock()
	defer d.mu.Unlock()
	d.cert, d.leaf = &pair, leaf
	return nil
}

// Loaded reports whether a certificate is loaded.
func (d *Dynamic) Loaded() bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.cert != nil
}

// NotAfter is the loaded certificate's expiry (zero when none).
func (d *Dynamic) NotAfter() time.Time {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.leaf == nil {
		return time.Time{}
	}
	return d.leaf.NotAfter
}

// TLSConfig serves the current certificate on every handshake.
func (d *Dynamic) TLSConfig() *tls.Config {
	return &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
			d.mu.RLock()
			defer d.mu.RUnlock()
			if d.cert == nil {
				return nil, ErrNoCertificate
			}
			return d.cert, nil
		},
	}
}

// CanServe reports whether the current certificate covers host.
func (d *Dynamic) CanServe(host string) error {
	d.mu.RLock()
	defer d.mu.RUnlock()
	if d.leaf == nil {
		return ErrNoCertificate
	}
	if err := d.leaf.VerifyHostname(host); err != nil {
		return fmt.Errorf("the relay's certificate doesn't cover %s", host)
	}
	return nil
}
