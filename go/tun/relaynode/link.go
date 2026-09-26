package relaynode

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	// claimRetry is how long a claim keeps trying an unreachable registry
	// before the relay ends the session (the agent reconnects).
	claimRetry = 10 * time.Second
	// ownersTTL is how long the relay's copy of the live tables is used
	// for forwarding decisions.
	ownersTTL = 5 * time.Second
)

// link implements relay.Cluster over the vnet.
type link struct {
	vnic    ifs.IVNic
	relayID string
	key     []byte

	mu      sync.Mutex
	owners  map[string]*tun.TunLiveTunnel // by name and by custom domain
	relays  map[string]*tun.TunRelay
	fetched time.Time
}

// ask sends a request to the claims engine.
func (l *link) ask(req *tun.TunClaimRequest) (*tun.TunClaimResponse, error) {
	req.RelayId = l.relayID
	resp := l.vnic.Request("", common.ClaimService, common.AreaLive, ifs.POST, req, common.RequestTimeout)
	if resp.Error() != nil {
		return nil, resp.Error()
	}
	out, ok := resp.Element().(*tun.TunClaimResponse)
	if !ok {
		return nil, fmt.Errorf("unexpected TunClaim reply %T", resp.Element())
	}
	return out, nil
}

// tell sends a request whose answer doesn't matter (logged on failure).
func (l *link) tell(req *tun.TunClaimRequest) {
	if _, err := l.ask(req); err != nil {
		l.vnic.Resources().Logger().Warning("registry ", req.Kind.String(), ": ", err.Error())
	}
}

func (l *link) ClaimTunnel(c relay.ClaimRequest) (int, error) {
	typ, err := common.TunnelTypeOf(protocol.TunnelTypeName(c.Type))
	if err != nil {
		return 0, err
	}
	req := &tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_CLAIM, SessionId: c.SessionID, AgentId: c.AgentID,
		TokenId: c.TokenID, MaxTunnels: int32(c.MaxTunnels), PortMin: int32(c.PortMin), PortMax: int32(c.PortMax),
		Tunnels: []*tun.TunLiveTunnel{{TunnelId: c.TunnelID, Name: c.Name, Type: typ, Hostname: c.Hostname,
			Domains: c.Domains, PublicPort: int32(c.PublicPort), AccessToken: c.AccessToken}}}
	deadline := time.Now().Add(claimRetry)
	for {
		resp, err := l.ask(req)
		if err == nil {
			if resp.Error != tun.TunClaimError_TUN_CLAIM_ERROR_UNSPECIFIED {
				return 0, &protocol.RemoteError{Code: wireCode(resp.Error), Message: resp.Message}
			}
			if len(resp.Tunnels) != 1 {
				return 0, fmt.Errorf("registry returned %d tunnels", len(resp.Tunnels))
			}
			l.invalidate()
			return int(resp.Tunnels[0].PublicPort), nil
		}
		if time.Now().After(deadline) {
			return 0, fmt.Errorf("%w: %v", relay.ErrClusterUnavailable, err)
		}
		time.Sleep(time.Second)
	}
}

func wireCode(e tun.TunClaimError) l8tunnel.ErrorCode {
	switch e {
	case tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN:
		return l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN
	case tun.TunClaimError_TUN_CLAIM_ERROR_MAX_TUNNELS, tun.TunClaimError_TUN_CLAIM_ERROR_FORBIDDEN:
		return l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN
	case tun.TunClaimError_TUN_CLAIM_ERROR_PORT_UNAVAILABLE:
		return l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE
	case tun.TunClaimError_TUN_CLAIM_ERROR_PORT_NOT_ALLOWED:
		return l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED
	}
	return l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST
}

func (l *link) ParkTunnels(sessionID string, names []string) {
	go l.tell(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_PARK, SessionId: sessionID, Names: names})
}

func (l *link) ReleaseTunnels(sessionID string, names []string) {
	go l.tell(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_RELEASE, SessionId: sessionID, Names: names})
}

func (l *link) AgentUp(a relay.AgentInfo) {
	transport := tun.TunAgentTransport_TUN_AGENT_TRANSPORT_TLS
	if a.WebSocket {
		transport = tun.TunAgentTransport_TUN_AGENT_TRANSPORT_WEBSOCKET
	}
	go l.tell(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_UP, Agent: &tun.TunAgent{
		AgentId: a.AgentID, TokenId: a.TokenID, TokenName: a.TokenName, CertSerial: a.CertSerial, SessionId: a.SessionID,
		Version: a.Version, Os: a.OS, Arch: a.Arch, PublicIp: a.PublicIP, Transport: transport, ConnectedAt: a.ConnectedAt.Unix()}})
}

func (l *link) AgentDown(agentID, sessionID string, reason relay.DisconnectReason) {
	go l.tell(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_DOWN, AgentId: agentID,
		SessionId: sessionID, Reason: disconnectReason(reason)})
}

func disconnectReason(r relay.DisconnectReason) tun.TunDisconnectReason {
	switch r {
	case relay.ReasonHeartbeat:
		return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_HEARTBEAT_TIMEOUT
	case relay.ReasonTokenRevoked:
		return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_TOKEN_REVOKED
	case relay.ReasonDrained:
		return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_DRAINED
	case relay.ReasonTakeover:
		return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_TAKEOVER
	case relay.ReasonOperator:
		return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_OPERATOR
	}
	return tun.TunDisconnectReason_TUN_DISCONNECT_REASON_AGENT_CLOSED
}

func (l *link) ForwardKey() []byte {
	return l.key
}

func (l *link) OwnerOf(host string) (string, bool) {
	rec, r := l.owner(host)
	if rec == nil || r == nil {
		return "", false
	}
	return net.JoinHostPort(r.PodIp, strconv.Itoa(int(r.TlsPort))), true
}

func (l *link) StreamOwnerOf(name string) (string, bool, bool) {
	rec, r := l.owner(name + "." + common.Cluster().BaseDomain)
	if rec == nil || r == nil {
		return "", false, false
	}
	return net.JoinHostPort(r.PodIp, strconv.Itoa(int(r.StreamPort))), rec.AccessToken, true
}

// owner finds the active tunnel serving host on another relay.
func (l *link) owner(host string) (*tun.TunLiveTunnel, *tun.TunRelay) {
	host = strings.ToLower(host)
	l.mu.Lock()
	defer l.mu.Unlock()
	if time.Since(l.fetched) > ownersTTL {
		l.fetch()
	}
	key := host
	if name := common.Cluster().Rules().TunnelName(host); name != "" {
		key = name
	}
	rec := l.owners[key]
	stale := rec == nil || rec.RelayId == l.relayID || rec.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE
	if stale && time.Since(l.fetched) > time.Second {
		// The copy says nobody (or this relay) serves it, yet the caller
		// found no local tunnel: it may have just moved. Look again, at
		// most once a second.
		l.fetch()
		rec = l.owners[key]
	}
	if rec == nil || rec.RelayId == l.relayID || rec.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
		return nil, nil
	}
	r := l.relays[rec.RelayId]
	if r == nil || r.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN || r.PodIp == "" {
		return nil, nil
	}
	return rec, r
}

// fetch reloads the live tables (callers hold l.mu).
func (l *link) fetch() {
	tunnels, err := l8common.GetEntities(common.LiveService, common.AreaLive, &tun.TunLiveTunnel{}, l.vnic)
	if err != nil {
		return
	}
	relays, err := l8common.GetEntities(common.RelayService, common.AreaLive, &tun.TunRelay{}, l.vnic)
	if err != nil {
		return
	}
	l.owners, l.relays = map[string]*tun.TunLiveTunnel{}, map[string]*tun.TunRelay{}
	for _, e := range tunnels {
		if t, ok := e.(*tun.TunLiveTunnel); ok && t.Name != "" {
			l.owners[t.Name] = t
			for _, d := range t.Domains {
				l.owners[d] = t
			}
		}
	}
	for _, e := range relays {
		if r, ok := e.(*tun.TunRelay); ok && r.RelayId != "" {
			l.relays[r.RelayId] = r
		}
	}
	l.fetched = time.Now()
}

func (l *link) invalidate() {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.fetched = time.Time{}
}
