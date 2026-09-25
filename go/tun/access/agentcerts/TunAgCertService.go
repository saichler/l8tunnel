// Package agentcerts is the TunAgCert service: records of the agent client
// certificates the agent CA issued. A certificate is accepted by the relays
// only while its record exists and isn't revoked. New records come from
// TunIssue, which returns the private key once.
package agentcerts

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.AgentCertService
	ServiceArea = common.AreaAccess
)

// ImportedCommonName marks a record imported from a standalone relay, which
// stores only certificate serials.
const ImportedCommonName = "(imported: serial only)"

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "CertId", newTunAgCertServiceCallback(),
		&tun.TunAgentCert{}, &tun.TunAgentCertList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Certs returns every certificate record.
func Certs(vnic ifs.IVNic) ([]*tun.TunAgentCert, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.TunAgentCert{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.TunAgentCert, 0, len(elems))
	for _, e := range elems {
		if c, ok := e.(*tun.TunAgentCert); ok && c.CertId != "" {
			out = append(out, c)
		}
	}
	return out, nil
}

// ValidSerials are the serials of a token's certificates that aren't
// revoked (what the relay accepts).
func ValidSerials(tokenID string, all []*tun.TunAgentCert) []string {
	var out []string
	for _, c := range all {
		if c.TokenId == tokenID && !c.Revoked {
			out = append(out, c.CertId)
		}
	}
	return out
}
