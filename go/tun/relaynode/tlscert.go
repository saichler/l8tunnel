package relaynode

import (
	"errors"
	"os"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// Environment variables naming a first-start certificate (the optional
// l8tunnel-tls Secret), used until one is uploaded in the UI.
const (
	TLSCertEnv = "L8TUNNEL_TLS_CERT"
	TLSKeyEnv  = "L8TUNNEL_TLS_KEY"
)

// loadCert loads the tunnel certificate uploaded on the TUNNEL_BASE domain,
// or the first-start files. An unchanged certificate isn't reloaded.
func (n *Node) loadCert() error {
	all, err := domains.Domains(n.vnic)
	if err == nil {
		for _, d := range all {
			if d.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE || d.CertFingerprint == "" {
				continue
			}
			if d.CertFingerprint == n.certFingerprint {
				return nil
			}
			certPEM, err := common.FetchFile(d.CertStoragePath, n.vnic)
			if err != nil {
				return err
			}
			keyPEM, err := common.FetchFile(d.KeyStoragePath, n.vnic)
			if err != nil {
				return err
			}
			if err := n.cert.Set(certPEM, keyPEM); err != nil {
				return err
			}
			n.certFingerprint = d.CertFingerprint
			n.vnic.Resources().Logger().Info("tunnel certificate loaded from ", d.Domain, ", expires ", n.cert.NotAfter().String())
			return nil
		}
	}
	if n.cert.Loaded() {
		return err
	}
	certFile, keyFile := os.Getenv(TLSCertEnv), os.Getenv(TLSKeyEnv)
	if certFile == "" || keyFile == "" {
		if err == nil {
			err = errors.New("no certificate uploaded on the tunnel base domain yet")
		}
		return err
	}
	certPEM, ferr := os.ReadFile(certFile)
	if ferr != nil {
		return ferr
	}
	keyPEM, ferr := os.ReadFile(keyFile)
	if ferr != nil {
		return ferr
	}
	return n.cert.Set(certPEM, keyPEM)
}
