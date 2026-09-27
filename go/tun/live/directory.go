package live

import (
	"strings"
	"sync"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"google.golang.org/protobuf/proto"

	"github.com/saichler/l8tunnel/go/tun/access/reservations"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// liveRefreshBackoff: after a failed refresh on a claim, claims use the
// cached copy alone for this long, so they don't wait on a down backend.
const liveRefreshBackoff = 30 * time.Second

// directory caches the reservations and edge site names claims are checked
// against. A failed refresh keeps the last good copy, so claims keep working
// while the management backend is down.
type directory struct {
	mu           sync.RWMutex
	reservations []*tun.TunReservation
	sites        map[string]bool
	loaded       bool
	downAt       time.Time
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

// refreshForClaim reloads the lists before a claim (claims are rare, like
// agent handshakes), unless a recent refresh failed.
func (d *directory) refreshForClaim(vnic ifs.IVNic) {
	d.mu.RLock()
	down := time.Since(d.downAt) < liveRefreshBackoff
	d.mu.RUnlock()
	if down {
		return
	}
	if err := d.refresh(vnic); err != nil {
		d.mu.Lock()
		d.downAt = time.Now()
		d.mu.Unlock()
		vnic.Resources().Logger().Warning("registry: refresh before a claim failed; using the cache: ", err.Error())
	}
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

// reserveAssigned keeps a reservation for every port a claim assigned, so a
// tunnel's port never changes: whatever restarts (agent, relays, registry),
// the reservation gives the name its port back and keeps other tokens off
// it. A reservation that names another port for the tunnel (its fixed
// port moved) follows the assigned one.
func (d *directory) reserveAssigned(req *tun.TunClaimRequest, resp *tun.TunClaimResponse, vnic ifs.IVNic) {
	if resp.Error != tun.TunClaimError_TUN_CLAIM_ERROR_UNSPECIFIED {
		return
	}
	tunnels := resp.Tunnels
	if req.Kind == tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE {
		// A relay's full state (after a registry restart): its tunnels, less
		// the ones reported as conflicts and simulated ones.
		conflict := map[string]bool{}
		for _, n := range resp.Conflicts {
			conflict[n] = true
		}
		tunnels = nil
		for _, t := range req.Tunnels {
			if !t.Simulated && !conflict[t.Name] {
				tunnels = append(tunnels, t)
			}
		}
	}
	existing := map[string]*tun.TunReservation{}
	for _, r := range d.Reservations() {
		existing[r.Name] = r
	}
	changed := false
	for _, t := range tunnels {
		if t.PublicPort == 0 {
			continue
		}
		token := t.TokenId
		if token == "" {
			token = req.TokenId
		}
		r := existing[t.Name]
		switch {
		case r == nil:
			n := &tun.TunReservation{Name: t.Name, TokenId: token, PublicPort: t.PublicPort,
				Note: "assigned automatically", CreatedAt: time.Now().Unix()}
			if _, err := l8common.PostEntity(reservations.ServiceName, reservations.ServiceArea, n, vnic); err != nil {
				vnic.Resources().Logger().Warning("registry: reserving port ", t.PublicPort, " for ", t.Name, ": ", err.Error())
				continue
			}
		case r.TokenId == token && r.PublicPort != t.PublicPort:
			u := proto.Clone(r).(*tun.TunReservation)
			u.PublicPort = t.PublicPort
			if err := l8common.PutEntity(reservations.ServiceName, reservations.ServiceArea, u, vnic); err != nil {
				vnic.Resources().Logger().Warning("registry: moving the reservation of ", t.Name, " to port ", t.PublicPort, ": ", err.Error())
				continue
			}
		default:
			continue
		}
		changed = true
	}
	if changed {
		if err := d.refresh(vnic); err != nil {
			vnic.Resources().Logger().Warning("registry: refresh after reserving ports: ", err.Error())
		}
	}
}
