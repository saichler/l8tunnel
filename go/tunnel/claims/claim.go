package claims

import (
	"errors"
	"fmt"

	"github.com/saichler/l8tunnel/go/tunnel/registry"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// claim registers every tunnel of the request or none of them.
func (e *Engine) claim(req *tun.TunClaimRequest) *tun.TunClaimResponse {
	if len(req.Tunnels) == 0 {
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "no tunnels to claim")
	}
	if req.AgentId == "" || req.TokenId == "" || req.SessionId == "" {
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "agentId, tokenId and sessionId are required")
	}
	reservations := e.dir.Reservations()
	staged := map[string]*tun.TunLiveTunnel{} // this request's records, by name
	stagedPorts := map[int32]string{}
	stagedDomains := map[string]string{}
	var takeovers []*tun.TunLiveTunnel
	for _, spec := range req.Tunnels {
		if spec.Simulated && !e.cfg.AllowSimulated {
			return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_FORBIDDEN, "simulated records aren't accepted here")
		}
		if staged[spec.Name] != nil {
			return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, fmt.Sprintf("tunnel name %q is requested twice", spec.Name))
		}
		rec, code, err := e.check(req, spec, reservations, staged, stagedPorts, stagedDomains)
		if err != nil {
			return refuse(code, err.Error())
		}
		if old := e.tunnels[spec.Name]; old != nil && old.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE && old.RelayId != req.RelayId {
			takeovers = append(takeovers, old)
		}
		staged[rec.Name] = rec
		if rec.PublicPort != 0 {
			stagedPorts[rec.PublicPort] = rec.Name
		}
		for _, d := range rec.Domains {
			stagedDomains[d] = rec.Name
		}
	}
	resp := &tun.TunClaimResponse{}
	for _, spec := range req.Tunnels {
		rec := staged[spec.Name]
		e.setTunnel(rec)
		resp.Tunnels = append(resp.Tunnels, cloneTunnel(rec))
	}
	// The agent reconnected through another relay before its old session
	// was noticed dead: tell the old relay to close that tunnel.
	for _, old := range takeovers {
		e.sink.Command(&tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_TAKEN_OVER,
			RelayId: old.RelayId, AgentId: old.AgentId, TunnelId: old.TunnelId})
	}
	return resp
}

// check applies the claim rules to one tunnel and builds its record.
func (e *Engine) check(req *tun.TunClaimRequest, spec *tun.TunLiveTunnel, reservations []*tun.TunReservation,
	staged map[string]*tun.TunLiveTunnel, stagedPorts map[int32]string, stagedDomains map[string]string) (*tun.TunLiveTunnel, tun.TunClaimError, error) {
	rules := e.cfg.Rules
	switch err := rules.CheckName(spec.Name); {
	case errors.Is(err, registry.ErrReservedName), errors.Is(err, registry.ErrInvalidName):
		return nil, tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, err
	}
	if host := spec.Name + "." + rules.BaseDomain; e.dir.IsSiteName(host) {
		return nil, tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, fmt.Errorf("tunnel name %q is taken", spec.Name)
	}
	var resv *tun.TunReservation
	for _, r := range reservations {
		if r.Name == spec.Name {
			resv = r
		}
	}
	if resv != nil && resv.TokenId != req.TokenId {
		return nil, tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, fmt.Errorf("tunnel name %q is taken", spec.Name)
	}
	holder := e.tunnels[spec.Name]
	var h *registry.Holder
	if holder != nil {
		h = &registry.Holder{TokenID: holder.TokenId, AgentID: holder.AgentId,
			Connected: holder.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE, SameSession: holder.SessionId == req.SessionId}
	}
	if _, err := registry.Decide(h, req.TokenId, req.AgentId, e.active(req.TokenId, spec.Name, staged), int(req.MaxTunnels)); err != nil {
		if errors.Is(err, registry.ErrMaxTunnels) {
			return nil, tun.TunClaimError_TUN_CLAIM_ERROR_MAX_TUNNELS, fmt.Errorf("the token may have at most %d tunnels", req.MaxTunnels)
		}
		return nil, tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, fmt.Errorf("tunnel name %q is taken", spec.Name)
	}
	rec := cloneTunnel(spec)
	rec.RelayId, rec.AgentId, rec.TokenId, rec.SessionId = req.RelayId, req.AgentId, req.TokenId, req.SessionId
	rec.State = tun.TunLiveState_TUN_LIVE_STATE_ACTIVE
	rec.ConnectedAt, rec.GraceUntil = e.now(), 0
	rec.ActiveConns, rec.TotalConns, rec.BytesIn, rec.BytesOut = 0, 0, 0, 0
	for _, d := range rec.Domains {
		if owner := e.byDomain[d]; (owner != "" && owner != rec.Name) || stagedDomains[d] != "" {
			return nil, tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, fmt.Errorf("domain %s is taken", d)
		}
	}
	rec.PublicPort = 0
	if hasPort(spec.Type) && !spec.AccessToken {
		port, code, err := e.port(req, spec, holder, resv, reservations, stagedPorts)
		if err != nil {
			return nil, code, err
		}
		rec.PublicPort = port
	}
	return rec, 0, nil
}

// active counts the token's connected tunnels, not counting name, and
// including the ones staged in this request.
func (e *Engine) active(tokenID, name string, staged map[string]*tun.TunLiveTunnel) int {
	n := 0
	for _, t := range e.tunnels {
		if t.TokenId == tokenID && t.Name != name && t.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE && staged[t.Name] == nil {
			n++
		}
	}
	return n + len(staged)
}

// port picks the tunnel's public port: the requested one, else the one it
// already holds, else its reservation's, else the lowest free port in the
// token's range.
func (e *Engine) port(req *tun.TunClaimRequest, spec, holder *tun.TunLiveTunnel, resv *tun.TunReservation,
	reservations []*tun.TunReservation, staged map[int32]string) (int32, tun.TunClaimError, error) {
	reservedByOther := func(p int32) bool {
		for _, r := range reservations {
			if r.PublicPort == p && r.Name != spec.Name {
				return true
			}
		}
		return false
	}
	free := func(p int32) bool {
		owner := e.byPort[p]
		return (owner == "" || owner == spec.Name) && staged[p] == "" && !reservedByOther(p)
	}
	lo, hi := req.PortMin, req.PortMax
	if lo == 0 {
		lo, hi = int32(e.cfg.Rules.PortMin), int32(e.cfg.Rules.PortMax)
	}
	want := spec.PublicPort
	if want == 0 && holder != nil && holder.PublicPort != 0 {
		want = holder.PublicPort
	}
	if want == 0 && resv != nil && resv.PublicPort != 0 {
		want = resv.PublicPort
	}
	if want != 0 {
		if want < int32(e.cfg.Rules.PortMin) || want > int32(e.cfg.Rules.PortMax) {
			return 0, tun.TunClaimError_TUN_CLAIM_ERROR_PORT_NOT_ALLOWED, fmt.Errorf("port %d is outside the relay's range %d-%d",
				want, e.cfg.Rules.PortMin, e.cfg.Rules.PortMax)
		}
		if !free(want) {
			return 0, tun.TunClaimError_TUN_CLAIM_ERROR_PORT_UNAVAILABLE, fmt.Errorf("port %d is unavailable: it is held by another tunnel", want)
		}
		return want, 0, nil
	}
	for p := lo; p <= hi; p++ {
		if free(p) {
			return p, 0, nil
		}
	}
	return 0, tun.TunClaimError_TUN_CLAIM_ERROR_PORT_UNAVAILABLE, fmt.Errorf("no free port in the range %d-%d", lo, hi)
}

func hasPort(t tun.TunTunnelType) bool {
	return t == tun.TunTunnelType_TUN_TUNNEL_TYPE_TCP || t == tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH
}
