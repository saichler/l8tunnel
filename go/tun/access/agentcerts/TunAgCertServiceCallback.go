package agentcerts

import (
	"errors"
	"fmt"
	"time"

	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

func newTunAgCertServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "TunAgentCert",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.TunAgentCert); return ok },
		// The ID is the certificate serial, set by TunIssue; there is
		// nothing to generate.
		SetID:    func(interface{}) {},
		Validate: validate,
		Changed:  common.PushToRelays,
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	c := e.(*tun.TunAgentCert)
	if action == ifs.POST {
		// TunIssue fills every field; an import from a standalone relay only
		// knows the serial.
		if c.CertId == "" || (c.Fingerprint == "" && c.CommonName != ImportedCommonName) {
			return nil, errors.New("issue agent certificates through TunIssue")
		}
		tok, err := tokens.Token(c.TokenId, vnic)
		if err != nil {
			return nil, err
		}
		if tok == nil {
			return nil, fmt.Errorf("token %s doesn't exist", c.TokenId)
		}
		if c.CreatedAt == 0 {
			c.CreatedAt = time.Now().Unix()
		}
		return nil, nil
	}
	// A certificate record is immutable except for revoked.
	all, err := Certs(vnic)
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if o.CertId != c.CertId {
			continue
		}
		if o.Revoked && !c.Revoked && action == ifs.PUT {
			return nil, errors.New("a revoked certificate can't be restored; issue a new one")
		}
		changed := (c.TokenId != "" && c.TokenId != o.TokenId) ||
			(c.Fingerprint != "" && c.Fingerprint != o.Fingerprint) ||
			(c.NotAfter != 0 && c.NotAfter != o.NotAfter)
		if changed {
			return nil, errors.New("only a certificate's revoked flag can change")
		}
		if action == ifs.PUT {
			revoked := c.Revoked
			c.TokenId, c.CommonName, c.NotBefore, c.NotAfter = o.TokenId, o.CommonName, o.NotBefore, o.NotAfter
			c.Fingerprint, c.CreatedAt, c.Revoked = o.Fingerprint, o.CreatedAt, revoked
		}
		return nil, nil
	}
	return nil, fmt.Errorf("certificate %s doesn't exist", c.CertId)
}
