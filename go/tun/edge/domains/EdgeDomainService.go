// Package domains is the EdgeDomain service: the sites behind the edge,
// with their uploaded certificates and port forwarding tables. The built-in
// TUNNEL_BASE row describes the relays' own ports.
package domains

import (
	"strings"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.DomainService
	ServiceArea = common.AreaEdge
)

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "DomainId", newEdgeDomainServiceCallback(),
		&tun.EdgeDomain{}, &tun.EdgeDomainList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Domains returns every edge domain.
func Domains(vnic ifs.IVNic) ([]*tun.EdgeDomain, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.EdgeDomain{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.EdgeDomain, 0, len(elems))
	for _, e := range elems {
		if d, ok := e.(*tun.EdgeDomain); ok && d.DomainId != "" {
			out = append(out, d)
		}
	}
	return out, nil
}

// Owner returns the SITE domain that host (exactly) belongs to, or "".
// A tunnel can't use a name that is an edge site.
func Owner(host string, vnic ifs.IVNic) (string, error) {
	all, err := Domains(vnic)
	if err != nil {
		return "", err
	}
	host = strings.ToLower(host)
	for _, d := range all {
		if d.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE {
			continue
		}
		if d.Domain == host {
			return d.Domain, nil
		}
		for _, a := range d.Aliases {
			if a == host {
				return d.Domain, nil
			}
		}
	}
	return "", nil
}
