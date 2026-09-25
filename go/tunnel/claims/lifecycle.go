package claims

import (
	"time"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// park holds a relay's tunnels for their token after the session ended.
// A tunnel another relay (or session) took over meanwhile is left alone.
func (e *Engine) park(req *tun.TunClaimRequest) {
	until := req.GraceUntil
	if until == 0 {
		until = e.cfg.Now().Add(e.cfg.Grace).Unix()
	}
	for _, name := range req.Names {
		rec := e.tunnels[name]
		if rec == nil || rec.RelayId != req.RelayId || (req.SessionId != "" && rec.SessionId != req.SessionId) {
			continue
		}
		rec = cloneTunnel(rec)
		rec.State, rec.GraceUntil, rec.ActiveConns = tun.TunLiveState_TUN_LIVE_STATE_GRACE, until, 0
		e.setTunnel(rec)
	}
}

// release frees a relay's tunnels now (a tunnel failed to open, or its
// token was revoked).
func (e *Engine) release(req *tun.TunClaimRequest) {
	for _, name := range req.Names {
		rec := e.tunnels[name]
		if rec != nil && rec.RelayId == req.RelayId && (req.SessionId == "" || rec.SessionId == req.SessionId) {
			e.deleteTunnel(name)
		}
	}
}

// announce takes a relay's full state: after a registry restart (the
// engine starts empty) or a relay restart. A name another relay holds for a
// different agent is reported as a conflict, and the announcing relay
// closes it. The relay's records it no longer reports are parked.
func (e *Engine) announce(req *tun.TunClaimRequest) *tun.TunClaimResponse {
	resp := &tun.TunClaimResponse{}
	if req.Relay != nil {
		if req.Relay.Simulated && !e.cfg.AllowSimulated {
			return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_FORBIDDEN, "simulated records aren't accepted here")
		}
		e.touchRelay(req.RelayId, req.Relay)
	}
	reported := map[string]bool{}
	for _, t := range req.Tunnels {
		if t.Simulated && !e.cfg.AllowSimulated {
			continue
		}
		if cur := e.tunnels[t.Name]; cur != nil && cur.RelayId != req.RelayId &&
			cur.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE && cur.AgentId != t.AgentId {
			resp.Conflicts = append(resp.Conflicts, t.Name)
			continue
		}
		rec := cloneTunnel(t)
		rec.RelayId = req.RelayId
		if rec.State == tun.TunLiveState_TUN_LIVE_STATE_UNSPECIFIED {
			rec.State = tun.TunLiveState_TUN_LIVE_STATE_ACTIVE
		}
		e.setTunnel(rec)
		reported[rec.Name] = true
	}
	until := e.cfg.Now().Add(e.cfg.Grace).Unix()
	for name, rec := range e.tunnels {
		if rec.RelayId == req.RelayId && !reported[name] && rec.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			rec = cloneTunnel(rec)
			rec.State, rec.GraceUntil = tun.TunLiveState_TUN_LIVE_STATE_GRACE, until
			e.setTunnel(rec)
		}
	}
	for _, a := range req.Agents {
		if a.Simulated && !e.cfg.AllowSimulated {
			continue
		}
		rec := cloneAgent(a)
		rec.RelayId = req.RelayId
		e.setAgent(rec)
	}
	return resp
}

// heartbeat refreshes the relay and the counters of its agents and tunnels.
func (e *Engine) heartbeat(req *tun.TunClaimRequest) {
	e.touchRelay(req.RelayId, req.Relay)
	for _, t := range req.Tunnels {
		rec := e.tunnels[t.Name]
		if rec == nil || rec.RelayId != req.RelayId || rec.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			continue
		}
		if rec.ActiveConns == t.ActiveConns && rec.TotalConns == t.TotalConns && rec.BytesIn == t.BytesIn && rec.BytesOut == t.BytesOut {
			continue
		}
		rec = cloneTunnel(rec)
		rec.ActiveConns, rec.TotalConns, rec.BytesIn, rec.BytesOut = t.ActiveConns, t.TotalConns, t.BytesIn, t.BytesOut
		e.setTunnel(rec)
	}
	now := e.now()
	for _, a := range req.Agents {
		rec := e.agents[a.AgentId]
		if rec == nil || rec.RelayId != req.RelayId || rec.SessionId != a.SessionId {
			continue
		}
		rec = cloneAgent(rec)
		rec.LastHeartbeat, rec.RttUs, rec.TunnelCount = a.LastHeartbeat, a.RttUs, a.TunnelCount
		rec.ActiveStreams, rec.BytesIn, rec.BytesOut, rec.LastSeen = a.ActiveStreams, a.BytesIn, a.BytesOut, now
		e.setAgent(rec)
	}
}

// touchRelay records a relay's report; the relay's state wins, except that
// a relay the engine considered lost is back up.
func (e *Engine) touchRelay(id string, r *tun.TunRelay) {
	rec := &tun.TunRelay{RelayId: id, State: tun.TunRelayState_TUN_RELAY_STATE_READY}
	if r != nil {
		rec = cloneRelay(r)
		rec.RelayId = id
	}
	if rec.State == tun.TunRelayState_TUN_RELAY_STATE_UNSPECIFIED || rec.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN {
		rec.State = tun.TunRelayState_TUN_RELAY_STATE_READY
	}
	rec.LastSeen = e.now()
	if old := e.relays[id]; old != nil && rec.StartedAt == 0 {
		rec.StartedAt = old.StartedAt
	}
	e.setRelay(rec)
}

// agentUp records an agent's new session.
func (e *Engine) agentUp(req *tun.TunClaimRequest) *tun.TunClaimResponse {
	a := req.Agent
	if a == nil || a.AgentId == "" || a.SessionId == "" {
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "agent with agentId and sessionId is required")
	}
	if a.Simulated && !e.cfg.AllowSimulated {
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_FORBIDDEN, "simulated records aren't accepted here")
	}
	rec := cloneAgent(a)
	now := e.now()
	rec.RelayId, rec.State, rec.GraceUntil = req.RelayId, tun.TunAgentState_TUN_AGENT_STATE_ONLINE, 0
	rec.DisconnectReason = tun.TunDisconnectReason_TUN_DISCONNECT_REASON_UNSPECIFIED
	if rec.ConnectedAt == 0 {
		rec.ConnectedAt = now
	}
	rec.LastSeen, rec.LastHeartbeat = now, now
	e.setAgent(rec)
	return &tun.TunClaimResponse{}
}

// agentDown moves an agent to GRACE (its names are held), unless a newer
// session of the same agent is already up.
func (e *Engine) agentDown(req *tun.TunClaimRequest) {
	rec := e.agents[req.AgentId]
	if rec == nil || rec.RelayId != req.RelayId || rec.SessionId != req.SessionId {
		return
	}
	e.downAgent(rec, req.Reason, e.cfg.Now())
}

func (e *Engine) downAgent(rec *tun.TunAgent, reason tun.TunDisconnectReason, now time.Time) {
	rec = cloneAgent(rec)
	rec.State, rec.DisconnectReason = tun.TunAgentState_TUN_AGENT_STATE_GRACE, reason
	rec.GraceUntil, rec.LastSeen, rec.ActiveStreams = now.Add(e.cfg.Grace).Unix(), now.Unix(), 0
	if reason == tun.TunDisconnectReason_TUN_DISCONNECT_REASON_TOKEN_REVOKED {
		// A revoked token's names aren't held.
		rec.State, rec.GraceUntil = tun.TunAgentState_TUN_AGENT_STATE_OFFLINE, 0
	}
	e.setAgent(rec)
}
