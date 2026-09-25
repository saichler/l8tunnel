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

// reconcile makes the live tables match the engine exactly, removing rows
// a client wrote or deleted directly.
func (r *Registry) reconcile() {
	tunnels, agents, relays := r.Engine.Snapshot()
	keepT := map[string]bool{}
	for _, t := range tunnels {
		keepT[t.Name] = true
		r.views.tunnels.put(t)
	}
	for _, e := range r.views.tunnels.all() {
		if t, ok := e.(*tun.TunLiveTunnel); ok && !keepT[t.Name] {
			r.views.tunnels.remove(&tun.TunLiveTunnel{Name: t.Name})
		}
	}
	keepA := map[string]bool{}
	for _, a := range agents {
		keepA[a.AgentId] = true
		r.views.agents.put(a)
	}
	for _, e := range r.views.agents.all() {
		if a, ok := e.(*tun.TunAgent); ok && !keepA[a.AgentId] {
			r.views.agents.remove(&tun.TunAgent{AgentId: a.AgentId})
		}
	}
	keepR := map[string]bool{}
	for _, rl := range relays {
		keepR[rl.RelayId] = true
		r.views.relays.put(rl)
	}
	for _, e := range r.views.relays.all() {
		if rl, ok := e.(*tun.TunRelay); ok && !keepR[rl.RelayId] {
			r.views.relays.remove(&tun.TunRelay{RelayId: rl.RelayId})
		}
	}
}
