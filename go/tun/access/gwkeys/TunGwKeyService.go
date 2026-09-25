// Package gwkeys is the TunGwKey service: SSH public keys allowed through
// the relays' SSH jump gateway, with the tunnels each may reach.
package gwkeys

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.GatewayKeyService
	ServiceArea = common.AreaAccess
)

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "KeyId", newTunGwKeyServiceCallback(),
		&tun.TunGatewayKey{}, &tun.TunGatewayKeyList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Keys returns every gateway key.
func Keys(vnic ifs.IVNic) ([]*tun.TunGatewayKey, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.TunGatewayKey{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.TunGatewayKey, 0, len(elems))
	for _, e := range elems {
		if k, ok := e.(*tun.TunGatewayKey); ok && k.KeyId != "" {
			out = append(out, k)
		}
	}
	return out, nil
}
