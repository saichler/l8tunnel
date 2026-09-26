package live

import (
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/claims"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	sweepInterval     = 5 * time.Second
	refreshInterval   = 30 * time.Second
	reconcileInterval = 30 * time.Second
)

// Registry is the running registry: engine, services and loops.
type Registry struct {
	Engine *claims.Engine
	views  *views
	dir    *directory
	vnic   ifs.IVNic
}

// Start activates the live tables and the action services, loads the
// management data claims are checked against, and asks every relay to
// re-announce its state (the engine starts empty).
func Start(vnic ifs.IVNic) *Registry {
	r := &Registry{views: activateViews(vnic), dir: &directory{}, vnic: vnic}
	r.Engine = claims.New(claims.Config{
		Rules:          common.Cluster().Rules(),
		AllowSimulated: common.AllowSimulated(),
	}, r.dir, &sink{views: r.views, vnic: vnic})
	activateAction(vnic, &ClaimHandler{}, r.Engine, common.ClaimService, &tun.TunClaimRequest{}, &tun.TunClaimResponse{})
	activateAction(vnic, &CtlHandler{}, r.Engine, common.CtlService, &tun.TunCtlCommand{}, &tun.TunCtlCommand{})
	if err := r.dir.refresh(vnic); err != nil {
		vnic.Resources().Logger().Warning("registry: management data not loaded yet: ", err.Error())
	}
	go r.loop()
	common.PushToRelays(&tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_REANNOUNCE}, ifs.POST, vnic)
	return r
}

func (r *Registry) loop() {
	sweep := time.NewTicker(sweepInterval)
	refresh := time.NewTicker(refreshInterval)
	reconcile := time.NewTicker(reconcileInterval)
	for {
		select {
		case <-sweep.C:
			r.Engine.Sweep()
		case <-refresh.C:
			if err := r.dir.refresh(r.vnic); err != nil {
				r.vnic.Resources().Logger().Warning("registry: refresh management data: ", err.Error())
			}
		case <-reconcile.C:
			r.reconcile()
		}
	}
}

// reconcile makes the live tables match the engine exactly: rows the
// engine has are replaced (or created when missing), rows it doesn't have
// are deleted.
func (r *Registry) reconcile() {
	tunnels, agents, relays := r.Engine.Snapshot()
	have := func(v *view, key func(interface{}) string) map[string]bool {
		out := map[string]bool{}
		for _, e := range v.all() {
			out[key(e)] = true
		}
		return out
	}
	tKey := func(e interface{}) string { return e.(*tun.TunLiveTunnel).Name }
	aKey := func(e interface{}) string { return e.(*tun.TunAgent).AgentId }
	rKey := func(e interface{}) string { return e.(*tun.TunRelay).RelayId }

	rows, keep := have(r.views.tunnels, tKey), map[string]bool{}
	for _, t := range tunnels {
		keep[t.Name] = true
		r.views.tunnels.apply(t, nil, changeFor(rows[t.Name]))
	}
	for name := range rows {
		if !keep[name] {
			r.views.tunnels.apply(nil, &tun.TunLiveTunnel{Name: name}, claims.Deleted)
		}
	}
	rows, keep = have(r.views.agents, aKey), map[string]bool{}
	for _, a := range agents {
		keep[a.AgentId] = true
		r.views.agents.apply(a, nil, changeFor(rows[a.AgentId]))
	}
	for id := range rows {
		if !keep[id] {
			r.views.agents.apply(nil, &tun.TunAgent{AgentId: id}, claims.Deleted)
		}
	}
	rows, keep = have(r.views.relays, rKey), map[string]bool{}
	for _, rl := range relays {
		keep[rl.RelayId] = true
		r.views.relays.apply(rl, nil, changeFor(rows[rl.RelayId]))
	}
	for id := range rows {
		if !keep[id] {
			r.views.relays.apply(nil, &tun.TunRelay{RelayId: id}, claims.Deleted)
		}
	}
}

func changeFor(exists bool) claims.Change {
	if exists {
		return claims.Updated
	}
	return claims.Created
}
