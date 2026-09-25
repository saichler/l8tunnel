package auth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"
)

// Agent certificates carry their token ID as a URI SAN.
const tokenURIPrefix = "l8tunnel:token:"

// AgentCA issues and verifies agent client certificates.
type AgentCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

// NewAgentCA creates a CA valid for 10 years.
func NewAgentCA() (*AgentCA, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randomSerial(),
		Subject:               pkix.Name{CommonName: "l8tunnel agent CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		MaxPathLenZero:        true,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &AgentCA{cert: cert, key: key}, nil
}

// LoadAgentCA parses a CA stored with PEM.
func LoadAgentCA(certPEM, keyPEM []byte) (*AgentCA, error) {
	cb, _ := pem.Decode(certPEM)
	kb, _ := pem.Decode(keyPEM)
	if cb == nil || kb == nil {
		return nil, fmt.Errorf("agent CA: invalid PEM")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent CA certificate: %w", err)
	}
	key, err := x509.ParseECPrivateKey(kb.Bytes)
	if err != nil {
		return nil, fmt.Errorf("agent CA key: %w", err)
	}
	return &AgentCA{cert: cert, key: key}, nil
}

// PEM returns the CA certificate and key.
func (ca *AgentCA) PEM() (certPEM, keyPEM []byte, err error) {
	der, err := x509.MarshalECPrivateKey(ca.key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.cert.Raw}),
		pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), nil
}

// Certificate is the CA certificate (for the relay's ClientCAs pool).
func (ca *AgentCA) Certificate() *x509.Certificate {
	return ca.cert
}

// IssuedCert is a new agent certificate; the key exists only here.
type IssuedCert struct {
	CertPEM []byte
	KeyPEM  []byte
	Serial  string
	Expires time.Time
}

// Issue creates a client certificate for a token, valid for days days.
func (ca *AgentCA) Issue(tok *TokenRecord, days int) (*IssuedCert, error) {
	if days < 1 || days > 3650 {
		return nil, fmt.Errorf("certificate validity must be 1-3650 days, not %d", days)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial := randomSerial()
	expires := time.Now().AddDate(0, 0, days)
	uri, _ := url.Parse(tokenURIPrefix + tok.ID)
	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: tok.Name},
		URIs:         []*url.URL{uri},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     expires,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		return nil, err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return nil, err
	}
	return &IssuedCert{
		CertPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		KeyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}),
		Serial:  serial.Text(16),
		Expires: expires,
	}, nil
}

// CertIdentity extracts the token ID and serial from an agent certificate
// that TLS has already verified against the CA.
func CertIdentity(cert *x509.Certificate) (tokenID, serial string, err error) {
	for _, u := range cert.URIs {
		if id, ok := strings.CutPrefix(u.String(), tokenURIPrefix); ok {
			return id, cert.SerialNumber.Text(16), nil
		}
	}
	return "", "", fmt.Errorf("certificate has no l8tunnel token identity")
}

// HasCertSerial reports whether the token issued a certificate serial.
func (r *TokenRecord) HasCertSerial(serial string) bool {
	for _, s := range r.CertSerials {
		if s == serial {
			return true
		}
	}
	return false
}

func randomSerial() *big.Int {
	n, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	return n
}
