package issue

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8tunnel/go/tun/access/agentcerts"
	"github.com/saichler/l8tunnel/go/tun/access/reservations"
	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// DefaultCertDays is an agent certificate's validity when none is given.
const DefaultCertDays = 365

// Post dispatches on the request kind.
func (h *IssueHandler) Post(elems ifs.IElements, vnic ifs.IVNic) ifs.IElements {
	req, ok := elems.Element().(*tun.TunIssueRequest)
	if !ok {
		return object.NewError("invalid TunIssueRequest")
	}
	var (
		resp *tun.TunIssueResponse
		err  error
	)
	switch req.Kind {
	case tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN:
		resp, err = issueToken(req, vnic)
	case tun.TunIssueKind_TUN_ISSUE_KIND_AGENT_CERT:
		resp, err = issueCert(req, vnic)
	case tun.TunIssueKind_TUN_ISSUE_KIND_IMPORT:
		resp, err = importExport(req, vnic)
	case tun.TunIssueKind_TUN_ISSUE_KIND_REVOKE:
		resp, err = revoke(req, vnic)
	default:
		err = errors.New("the request kind is required")
	}
	if err != nil {
		return object.NewError(err.Error())
	}
	resp.Kind = req.Kind
	return object.New(nil, resp)
}

func issueToken(req *tun.TunIssueRequest, vnic ifs.IVNic) (*tun.TunIssueResponse, error) {
	policy, err := common.PolicyToAuth(req.Policy)
	if err != nil {
		return nil, err
	}
	plaintext, rec, err := auth.NewToken(req.TokenName, policy)
	if err != nil {
		return nil, err
	}
	t := &tun.TunToken{
		TokenId:     rec.ID,
		Name:        rec.Name,
		Description: req.TokenDescription,
		SecretHash:  string(rec.Hash),
		Policy:      req.Policy,
		CreatedAt:   time.Now().Unix(),
	}
	if _, err := l8common.PostEntity(common.TokenService, common.AreaAccess, t, vnic); err != nil {
		return nil, err
	}
	common.PostSecurityEvent(vnic, "token.issued", t.TokenId, t.Name, "agent token "+t.Name+" issued")
	return &tun.TunIssueResponse{TokenId: t.TokenId, Token: plaintext}, nil
}

func issueCert(req *tun.TunIssueRequest, vnic ifs.IVNic) (*tun.TunIssueResponse, error) {
	tok, err := tokens.Token(req.TokenId, vnic)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, fmt.Errorf("token %s doesn't exist", req.TokenId)
	}
	ca, err := loadAgentCA()
	if err != nil {
		return nil, err
	}
	rec, err := common.TokenRecord(tok, nil)
	if err != nil {
		return nil, err
	}
	days := int(req.CertDays)
	if days == 0 {
		days = DefaultCertDays
	}
	issued, err := ca.Issue(rec, days)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(issued.CertPEM)
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(leaf.Raw)
	c := &tun.TunAgentCert{
		CertId:      issued.Serial,
		TokenId:     tok.TokenId,
		CommonName:  leaf.Subject.CommonName,
		NotBefore:   leaf.NotBefore.Unix(),
		NotAfter:    leaf.NotAfter.Unix(),
		Fingerprint: hex.EncodeToString(sum[:]),
		CreatedAt:   time.Now().Unix(),
	}
	if _, err := l8common.PostEntity(common.AgentCertService, common.AreaAccess, c, vnic); err != nil {
		return nil, err
	}
	common.PostSecurityEvent(vnic, "agent-cert.issued", c.CertId, tok.Name,
		"agent certificate "+c.CertId+" issued for token "+tok.Name)
	return &tun.TunIssueResponse{
		TokenId: tok.TokenId, CertPem: string(issued.CertPEM), KeyPem: string(issued.KeyPEM),
		CertId: issued.Serial, Expires: issued.Expires.Unix(),
	}, nil
}

// loadAgentCA reads the agent CA from the files of the l8tunnel-agent-ca
// Secret named in cluster.yaml.
func loadAgentCA() (*auth.AgentCA, error) {
	files := common.Cluster().AgentCA
	if files.Cert == "" || files.Key == "" {
		return nil, errors.New("no agent CA is configured (cluster.yaml agent_ca)")
	}
	certPEM, err := os.ReadFile(files.Cert)
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	keyPEM, err := os.ReadFile(files.Key)
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	return auth.LoadAgentCA(certPEM, keyPEM)
}

// revoke deletes a token with its certificates and reservations, then tells
// the relays, which drop the token's agents for good.
func revoke(req *tun.TunIssueRequest, vnic ifs.IVNic) (*tun.TunIssueResponse, error) {
	tok, err := tokens.Token(req.TokenId, vnic)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, fmt.Errorf("token %s doesn't exist", req.TokenId)
	}
	resp := &tun.TunIssueResponse{TokenId: tok.TokenId}
	// The token goes first, so its agents can't reconnect meanwhile.
	if err := common.DeleteEntity(common.TokenService, common.AreaAccess, &tun.TunToken{TokenId: tok.TokenId}, vnic); err != nil {
		return nil, err
	}
	common.PushToRelays(&tun.TunToken{TokenId: tok.TokenId}, ifs.DELETE, vnic)
	certs, err := agentcerts.Certs(vnic)
	if err != nil {
		return nil, err
	}
	for _, c := range certs {
		if c.TokenId != tok.TokenId {
			continue
		}
		if err := common.DeleteEntity(common.AgentCertService, common.AreaAccess, &tun.TunAgentCert{CertId: c.CertId}, vnic); err != nil {
			return nil, err
		}
		resp.RevokedCerts++
	}
	list, err := reservations.Reservations(vnic)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		if r.TokenId != tok.TokenId {
			continue
		}
		if err := common.DeleteEntity(common.ReservationService, common.AreaAccess, &tun.TunReservation{ReservationId: r.ReservationId}, vnic); err != nil {
			return nil, err
		}
		resp.RemovedReservations++
	}
	common.PostSecurityEvent(vnic, "token.revoked", tok.TokenId, tok.Name, fmt.Sprintf(
		"agent token %s revoked (%d certificates, %d reservations removed)", tok.Name, resp.RevokedCerts, resp.RemovedReservations))
	return resp, nil
}
