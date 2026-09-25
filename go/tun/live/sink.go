package live

import (
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// sink mirrors the engine's changes into the live tables and pushes its
// commands to the relays.
type sink struct {
	views *views
	vnic  ifs.IVNic
}

func (s *sink) TunnelChanged(r *tun.TunLiveTunnel, deleted bool) {
	if deleted {
		s.views.tunnels.remove(&tun.TunLiveTunnel{Name: r.Name})
		return
	}
	s.views.tunnels.put(r)
}

func (s *sink) AgentChanged(r *tun.TunAgent, deleted bool) {
	if deleted {
		s.views.agents.remove(&tun.TunAgent{AgentId: r.AgentId})
		return
	}
	s.views.agents.put(r)
}

func (s *sink) RelayChanged(r *tun.TunRelay, deleted bool) {
	if deleted {
		s.views.relays.remove(&tun.TunRelay{RelayId: r.RelayId})
		return
	}
	s.views.relays.put(r)
}

// Command reaches the relays through their TunRlyCtl listener; a command
// for one relay carries its ID and the others ignore it.
func (s *sink) Command(cmd *tun.TunCtlCommand) {
	// Sent asynchronously: the engine holds its lock while it reports.
	go common.PushToRelays(cmd, ifs.POST, s.vnic)
}
