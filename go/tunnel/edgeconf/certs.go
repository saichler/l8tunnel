package edgeconf

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// ExpiringWithin is when a certificate's status becomes EXPIRING.
const ExpiringWithin = 30 * 24 * time.Hour

// CertSummary describes an uploaded certificate chain and key.
type CertSummary struct {
	Subject     string
	SANs        []string
	Issuer      string
	NotAfter    time.Time
	Fingerprint string // SHA-256 of the leaf, hex
	Status      tun.EdgeCertStatus
	// Problem explains a MISMATCH or EXPIRED status.
	Problem string
}

// SummarizeCert parses a PEM chain and key, checks that the key belongs
// to the leaf and that the leaf covers every name (wildcard names such as
// *.example.com must be covered by a matching wildcard), and reports its
// validity at now. It returns an error only when the files can't be parsed
// at all; a certificate that parses but doesn't fit gets a MISMATCH or
// EXPIRED status with Problem set.
func SummarizeCert(certPEM, keyPEM []byte, names []string, now time.Time) (CertSummary, error) {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return CertSummary{}, fmt.Errorf("the certificate and key don't form a valid pair: %w", err)
	}
	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return CertSummary{}, fmt.Errorf("parse the certificate: %w", err)
	}
	sum := sha256.Sum256(leaf.Raw)
	s := CertSummary{
		Subject:     leaf.Subject.CommonName,
		SANs:        append([]string(nil), leaf.DNSNames...),
		Issuer:      leaf.Issuer.CommonName,
		NotAfter:    leaf.NotAfter,
		Fingerprint: hex.EncodeToString(sum[:]),
		Status:      tun.EdgeCertStatus_EDGE_CERT_STATUS_VALID,
	}
	for _, n := range names {
		if !covers(leaf, n) {
			s.Status = tun.EdgeCertStatus_EDGE_CERT_STATUS_MISMATCH
			s.Problem = "the certificate doesn't cover " + n
			return s, nil
		}
	}
	switch {
	case now.After(leaf.NotAfter):
		s.Status = tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRED
		s.Problem = "the certificate expired on " + leaf.NotAfter.UTC().Format(time.DateOnly)
	case now.Before(leaf.NotBefore):
		s.Status = tun.EdgeCertStatus_EDGE_CERT_STATUS_MISMATCH
		s.Problem = "the certificate isn't valid before " + leaf.NotBefore.UTC().Format(time.DateOnly)
	case leaf.NotAfter.Sub(now) < ExpiringWithin:
		s.Status = tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRING
	}
	return s, nil
}

// covers reports whether leaf serves name. A wildcard name needs the same
// wildcard in the certificate: *.example.com isn't served by a certificate
// for www.example.com.
func covers(leaf *x509.Certificate, name string) bool {
	if strings.HasPrefix(name, "*.") {
		for _, san := range leaf.DNSNames {
			if strings.EqualFold(san, name) {
				return true
			}
		}
		return false
	}
	return leaf.VerifyHostname(name) == nil
}
