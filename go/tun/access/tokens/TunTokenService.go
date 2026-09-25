// Package tokens is the TunToken service: agent tokens, stored as bcrypt
// hashes. New tokens come from TunIssue, which returns the plaintext once.
package tokens

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.TokenService
	ServiceArea = common.AreaAccess
)

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "TokenId", newTunTokenServiceCallback(),
		&tun.TunToken{}, &tun.TunTokenList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Token returns the token with the ID, or nil.
func Token(tokenID string, vnic ifs.IVNic) (*tun.TunToken, error) {
	result, err := l8common.GetEntity(ServiceName, ServiceArea, &tun.TunToken{TokenId: tokenID}, vnic)
	if err != nil || result == nil {
		return nil, err
	}
	t, _ := result.(*tun.TunToken)
	if t == nil || t.TokenId == "" {
		return nil, nil
	}
	return t, nil
}

// Tokens returns every token.
func Tokens(vnic ifs.IVNic) ([]*tun.TunToken, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.TunToken{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.TunToken, 0, len(elems))
	for _, e := range elems {
		if t, ok := e.(*tun.TunToken); ok && t.TokenId != "" {
			out = append(out, t)
		}
	}
	return out, nil
}
