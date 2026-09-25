package live

import (
	"strings"
	"sync"

	"github.com/saichler/l8tunnel/go/tun/access/reservations"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// directory caches the reservations and edge site names claims are checked
// against. A failed refresh keeps the last good copy, so claims keep working
// while the management backend is down.
type directory struct {
	mu           sync.RWMutex
	reservations []*tun.TunReservation
	sites        map[string]bool
	loaded       bool
}

func (d *directory) Reservations() []*tun.TunReservation {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.reservations
}

func (d *directory) IsSiteName(host string) bool {
	d.mu.RLock()
	defer d.mu.RUnlock()
	return d.sites[strings.ToLower(host)]
}

// refresh reloads both lists from the backend.
func (d *directory) refresh(vnic ifs.IVNic) error {
	resv, err := reservations.Reservations(vnic)
	if err != nil {
		return err
	}
	all, err := domains.Domains(vnic)
	if err != nil {
		return err
	}
	sites := map[string]bool{}
	for _, dom := range all {
		if dom.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE {
			continue
		}
		sites[dom.Domain] = true
		for _, a := range dom.Aliases {
			sites[a] = true
		}
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	d.reservations, d.sites, d.loaded = resv, sites, true
	return nil
}
