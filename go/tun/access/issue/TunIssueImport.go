package issue

import (
	"fmt"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/access/agentcerts"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// importExport loads a standalone relay's export. Token IDs and hashes are
// kept, so agents keep their tokens; certificate serials become records, so
// agents keep their certificates too (the agent CA moves separately, as a
// Secret). Objects that already exist are skipped, so an import can be
// re-run.
func importExport(req *tun.TunIssueRequest, vnic ifs.IVNic) (*tun.TunIssueResponse, error) {
	exp, err := store.ParseExport([]byte(req.ImportJson))
	if err != nil {
		return nil, err
	}
	resp := &tun.TunIssueResponse{}
	for _, rec := range exp.Tokens {
		policy, err := common.PolicyFromAuth(rec.Policy)
		if err != nil {
			return nil, fmt.Errorf("token %s: %w", rec.Name, err)
		}
		exists, err := l8common.EntityExists(common.TokenService, common.AreaAccess, &tun.TunToken{TokenId: rec.ID}, vnic)
		if err != nil {
			return nil, err
		}
		if !exists {
			t := &tun.TunToken{TokenId: rec.ID, Name: rec.Name, SecretHash: string(rec.Hash), Policy: policy,
				CreatedAt: rec.Created.Unix(), Description: "imported from a standalone relay"}
			if _, err := l8common.PostEntity(common.TokenService, common.AreaAccess, t, vnic); err != nil {
				return nil, fmt.Errorf("token %s: %w", rec.Name, err)
			}
			resp.ImportedTokens++
		}
		for _, serial := range rec.CertSerials {
			c := &tun.TunAgentCert{CertId: serial, TokenId: rec.ID, CommonName: agentcerts.ImportedCommonName,
				CreatedAt: time.Now().Unix()}
			if exists, err := l8common.EntityExists(common.AgentCertService, common.AreaAccess, &tun.TunAgentCert{CertId: serial}, vnic); err != nil {
				return nil, err
			} else if !exists {
				if _, err := l8common.PostEntity(common.AgentCertService, common.AreaAccess, c, vnic); err != nil {
					return nil, fmt.Errorf("certificate %s: %w", serial, err)
				}
			}
		}
	}
	for _, r := range exp.Reservations {
		posted, err := postIfNew(common.ReservationService, &tun.TunReservation{Name: r.Name, TokenId: r.TokenID,
			PublicPort: int32(r.Port), CreatedAt: r.Created.Unix()}, func(o interface{}) bool {
			return o.(*tun.TunReservation).Name == r.Name
		}, &tun.TunReservation{}, vnic)
		if err != nil {
			return nil, fmt.Errorf("reservation %s: %w", r.Name, err)
		}
		if posted {
			resp.ImportedReservations++
		}
	}
	for _, k := range exp.GatewayKeys {
		posted, err := postIfNew(common.GatewayKeyService, &tun.TunGatewayKey{Name: k.Name, PublicKey: k.PublicKey,
			Tunnels: k.Tunnels, CreatedAt: k.Created.Unix()}, func(o interface{}) bool {
			return o.(*tun.TunGatewayKey).Fingerprint == k.Fingerprint
		}, &tun.TunGatewayKey{}, vnic)
		if err != nil {
			return nil, fmt.Errorf("gateway key %s: %w", k.Name, err)
		}
		if posted {
			resp.ImportedGatewayKeys++
		}
	}
	common.PostSecurityEvent(vnic, "import.done", "", "standalone export", fmt.Sprintf(
		"imported %d tokens, %d reservations, %d gateway keys", resp.ImportedTokens, resp.ImportedReservations, resp.ImportedGatewayKeys))
	return resp, nil
}

// postIfNew posts obj unless an existing object of its service matches.
func postIfNew(service string, obj interface{}, matches func(interface{}) bool, all interface{}, vnic ifs.IVNic) (bool, error) {
	existing, err := l8common.GetEntities(service, common.AreaAccess, all, vnic)
	if err != nil {
		return false, err
	}
	for _, e := range existing {
		if e != nil && matches(e) {
			return false, nil
		}
	}
	_, err = l8common.PostEntity(service, common.AreaAccess, obj, vnic)
	return err == nil, err
}
