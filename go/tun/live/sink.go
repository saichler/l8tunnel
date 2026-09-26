package live

import (
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/claims"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// sink mirrors the engine's changes into the live tables and pushes its
// commands to the relays.
type sink struct {
	views *views
	vnic  ifs.IVNic
}

func (s *sink) TunnelChanged(r *tun.TunLiveTunnel, change claims.Change) {
	s.views.tunnels.apply(r, &tun.TunLiveTunnel{Name: r.Name}, change)
	if change != claims.Updated {
		// Edges and relays route by this table: tell them it changed, so
		// they don't route on a stale copy (counter updates don't matter).
		go common.PushToEdges(r, ifs.POST, s.vnic)
		go common.PushToRelays(r, ifs.POST, s.vnic)
	}
}

func (s *sink) AgentChanged(r *tun.TunAgent, change claims.Change) {
	s.views.agents.apply(r, &tun.TunAgent{AgentId: r.AgentId}, change)
}

func (s *sink) RelayChanged(r *tun.TunRelay, change claims.Change) {
	s.views.relays.apply(r, &tun.TunRelay{RelayId: r.RelayId}, change)
}

// Command reaches the relays through their TunRlyCtl listener; a command
// for one relay carries its ID and the others ignore it.
func (s *sink) Command(cmd *tun.TunCtlCommand) {
	// Sent asynchronously: the engine holds its lock while it reports.
	go common.PushToRelays(cmd, ifs.POST, s.vnic)
}
