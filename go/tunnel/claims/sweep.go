package claims

import (
	"errors"
	"fmt"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// Sweep applies time: lost relays, expired grace periods, and the
// retention of offline agents and lost relays. The registry calls it every
// few seconds. Simulated records never expire.
func (e *Engine) Sweep() {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.cfg.Now()
	lostBefore := now.Add(-e.cfg.RelayTimeout).Unix()
	for id, r := range e.relays {
		if r.Simulated {
			continue
		}
		switch {
		case r.State != tun.TunRelayState_TUN_RELAY_STATE_DOWN && r.LastSeen < lostBefore:
			e.lostRelay(id, r)
		case r.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN && r.LastSeen < now.Add(-e.cfg.DownRetention).Unix():
			delete(e.relays, id)
			e.sink.RelayChanged(cloneRelay(r), Deleted)
		}
	}
	for name, t := range e.tunnels {
		if !t.Simulated && t.State == tun.TunLiveState_TUN_LIVE_STATE_GRACE && t.GraceUntil <= now.Unix() {
			e.deleteTunnel(name)
		}
	}
	for id, a := range e.agents {
		if a.Simulated {
			continue
		}
		switch {
		case a.State == tun.TunAgentState_TUN_AGENT_STATE_GRACE && a.GraceUntil <= now.Unix():
			rec := cloneAgent(a)
			rec.State, rec.GraceUntil = tun.TunAgentState_TUN_AGENT_STATE_OFFLINE, 0
			e.setAgent(rec)
		case a.State == tun.TunAgentState_TUN_AGENT_STATE_OFFLINE && a.LastSeen < now.Add(-e.cfg.OfflineRetention).Unix():
			delete(e.agents, id)
			e.sink.AgentChanged(cloneAgent(a), Deleted)
		}
	}
}

// lostRelay marks a silent relay down and parks everything it served; its
// agents reconnect elsewhere and reclaim their names.
func (e *Engine) lostRelay(id string, r *tun.TunRelay) {
	now := e.cfg.Now()
	rec := cloneRelay(r)
	rec.State, rec.Sessions, rec.Tunnels = tun.TunRelayState_TUN_RELAY_STATE_DOWN, 0, 0
	e.setRelay(rec)
	until := now.Add(e.cfg.Grace).Unix()
	for _, t := range e.tunnels {
		if t.RelayId == id && t.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			park := cloneTunnel(t)
			park.State, park.GraceUntil, park.ActiveConns = tun.TunLiveState_TUN_LIVE_STATE_GRACE, until, 0
			e.setTunnel(park)
		}
	}
	for _, a := range e.agents {
		if a.RelayId == id && a.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
			e.downAgent(a, tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_LOST, now)
		}
	}
}

// ErrNotFound: the command's target doesn't exist (or isn't connected).
var ErrNotFound = errors.New("not found")

// Command applies an operator's action and forwards it to the relay that
// must carry it out.
func (e *Engine) Command(cmd *tun.TunCtlCommand) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	switch cmd.Kind {
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DRAIN, tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_RESUME:
		r := e.relays[cmd.RelayId]
		if r == nil || r.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN {
			return fmt.Errorf("relay %q: %w", cmd.RelayId, ErrNotFound)
		}
		rec := cloneRelay(r)
		rec.State = tun.TunRelayState_TUN_RELAY_STATE_READY
		if cmd.Kind == tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DRAIN {
			rec.State = tun.TunRelayState_TUN_RELAY_STATE_DRAINING
		}
		e.setRelay(rec)
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_AGENT:
		a := e.agents[cmd.AgentId]
		if a == nil || a.State != tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
			return fmt.Errorf("agent %q isn't connected: %w", cmd.AgentId, ErrNotFound)
		}
		cmd.RelayId = a.RelayId
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_TUNNEL:
		var found *tun.TunLiveTunnel
		for _, t := range e.tunnels {
			if t.TunnelId == cmd.TunnelId && t.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
				found = t
			}
		}
		if found == nil {
			return fmt.Errorf("tunnel %q isn't connected: %w", cmd.TunnelId, ErrNotFound)
		}
		cmd.RelayId, cmd.AgentId = found.RelayId, found.AgentId
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_REANNOUNCE:
	default:
		return fmt.Errorf("unsupported command %s", cmd.Kind)
	}
	e.sink.Command(cmd)
	return nil
}
