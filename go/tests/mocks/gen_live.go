package mocks

import (
	"fmt"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// The simulated live records (plan §5.3): marked simulated, never routed
// to and never expired. The backend and the registry accept them only with
// L8TUNNEL_ALLOW_SIMULATED (KIND and local mode). The registry keeps them
// in memory, so they're gone after it restarts.

const (
	simRelays  = 3
	simAgents  = 25
	simTunnels = 40
)

func agentID(i int, tag string) string { return fmt.Sprintf("sim-agent-%02d%s", i+1, tag) }
func relayID(i int, tag string) string { return fmt.Sprintf("sim-relay-%d%s", i, tag) }

// Phase 6: a simulated edge node (the relays come with their agents and
// tunnels in phases 7 and 8).
func generateEdgeNode(c *Client, s *MockDataStore, tag string) error {
	now := time.Now().Unix()
	id := "sim-edge" + tag
	node := &tun.EdgeNode{EdgeId: id, NodeIp: "10.99.1.1", Version: "v1.6.2", ConfigVersion: now,
		StartedAt: now - 86400*3, ActiveConns: 42, TotalConns: 18230, BytesIn: 9_800_000_000, BytesOut: 31_200_000_000,
		Simulated: true,
		Listeners: []*tun.EdgeListenerStatus{
			{Port: 443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TLS, Bound: true, Domains: []string{"demo-shop.invalid"}},
			{Port: 80, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_HTTP, Bound: true, Domains: []string{"demo-shop.invalid"}},
			{Port: 41000, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP, Bound: false, Error: "listen tcp :41000: bind: address already in use",
				Domains: []string{"demo-shop.invalid"}},
		},
		Backends: []*tun.EdgeBackendStatus{
			{Domain: "shop/https", ListenPort: 443, Target: "10.20.0.10:8080", Healthy: true, ActiveConns: 12, LastCheck: now},
			{Domain: "shop/https", ListenPort: 443, Target: "10.20.0.11:8080", Healthy: false, LastError: "connection refused", LastCheck: now},
		}}
	if err := post(c, common.AreaEdge, common.EdgeNodeService, node, nil); err != nil {
		return err
	}
	s.TunEdgeIDs = append(s.TunEdgeIDs, id)
	return nil
}

// Phases 7 and 8: simulated relays with their agents (every state,
// transport, OS and a few older versions) and tunnels (every type, active
// and in grace), each relay announced to the registry in one claim.
func generateLive(c *Client, s *MockDataStore, tag string) error {
	if len(s.TunTokenIDs) == 0 {
		return fmt.Errorf("the live records need the tokens of phase 1")
	}
	now := time.Now().Unix()
	relays := make([]*tun.TunClaimRequest, simRelays)
	for r := range relays {
		state := tun.TunRelayState_TUN_RELAY_STATE_READY
		if r == 2 {
			state = tun.TunRelayState_TUN_RELAY_STATE_DRAINING
		}
		relays[r] = &tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE, RelayId: relayID(r, tag),
			Relay: &tun.TunRelay{RelayId: relayID(r, tag), PodIp: fmt.Sprintf("10.99.0.%d", 10+r), TlsPort: 8443, HttpPort: 8080,
				StreamPort: 8444, GatewayPort: 2222, OpsPort: 9100, State: state, Version: "v1.6.2", StartedAt: now - 86400,
				LastSeen: now, CertNotAfter: now + 86400*60, BytesIn: int64(r+1) * 7_000_000_000, BytesOut: int64(r+1) * 21_000_000_000,
				Simulated: true}}
	}
	reasons := []tun.TunDisconnectReason{tun.TunDisconnectReason_TUN_DISCONNECT_REASON_HEARTBEAT_TIMEOUT,
		tun.TunDisconnectReason_TUN_DISCONNECT_REASON_TOKEN_REVOKED, tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_DRAINED,
		tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_LOST, tun.TunDisconnectReason_TUN_DISCONNECT_REASON_TAKEOVER,
		tun.TunDisconnectReason_TUN_DISCONNECT_REASON_AGENT_CLOSED, tun.TunDisconnectReason_TUN_DISCONNECT_REASON_OPERATOR}
	types := []tun.TunTunnelType{tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH, tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP,
		tun.TunTunnelType_TUN_TUNNEL_TYPE_TCP, tun.TunTunnelType_TUN_TUNNEL_TYPE_TLS}
	agents := make([]*tun.TunAgent, simAgents)
	for i := range agents {
		t := i % len(s.TunTokenIDs)
		a := &tun.TunAgent{AgentId: agentID(i, tag), TokenId: s.TunTokenIDs[t], TokenName: s.TunTokenNames[t],
			SessionId: ifs.NewUuid(), Version: agentVersions[i%len(agentVersions)], Os: agentOS[i%len(agentOS)],
			Arch: agentArch[i%len(agentArch)], PublicIp: publicIPs[i%len(publicIPs)],
			Transport: tun.TunAgentTransport(1 + i%3), Simulated: true}
		switch {
		case i < simAgents*6/10: // the first 60% online
			a.State, a.ConnectedAt, a.LastHeartbeat, a.LastSeen = tun.TunAgentState_TUN_AGENT_STATE_ONLINE, now-int64(600*(i+1)), now, now
			a.RttUs, a.ActiveStreams = int64(8000+i*1500), int64(i%5)
			a.BytesIn, a.BytesOut = int64(i+1)*90_000_000, int64(i+1)*240_000_000
		case i < simAgents*8/10: // the next 20% in grace
			a.State, a.GraceUntil, a.LastSeen = tun.TunAgentState_TUN_AGENT_STATE_GRACE, now+120, now-30
			a.DisconnectReason = tun.TunDisconnectReason_TUN_DISCONNECT_REASON_HEARTBEAT_TIMEOUT
		default: // offline, each reason
			a.State, a.LastSeen = tun.TunAgentState_TUN_AGENT_STATE_OFFLINE, now-int64(3600*(i-simAgents*8/10+1))
			a.DisconnectReason = reasons[i%len(reasons)]
		}
		agents[i] = a
		req := relays[i%simRelays]
		req.Agents = append(req.Agents, a)
		s.TunAgentIDs = append(s.TunAgentIDs, a.AgentId)
	}
	for i := 0; i < simTunnels; i++ {
		a := agents[i%simAgents]
		if a.State == tun.TunAgentState_TUN_AGENT_STATE_OFFLINE {
			a = agents[i%(simAgents*8/10)] // offline agents hold no tunnels
		}
		typ := types[i%len(types)]
		t := &tun.TunLiveTunnel{TunnelId: ifs.NewUuid(), Name: fmt.Sprintf("%s-%02d%s", tunnelPrefixes[i%len(tunnelPrefixes)], i+1, tag),
			Type: typ, AgentId: a.AgentId, TokenId: a.TokenId, SessionId: a.SessionId, ConnectedAt: now - int64(300*(i+1)),
			TotalConns: int64(10 + i*7), BytesIn: int64(i+1) * 12_000_000, BytesOut: int64(i+1) * 55_000_000, Simulated: true}
		if typ == tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH || typ == tun.TunTunnelType_TUN_TUNNEL_TYPE_TCP {
			t.PublicPort = 22500 + s.portOffset*40 + int32(i)
		}
		if typ == tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP && i%3 == 0 {
			t.Domains = []string{fmt.Sprintf("app%d%s.example.test", i, tag)}
		}
		if i < simTunnels*6/10 && a.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
			t.State, t.ActiveConns = tun.TunLiveState_TUN_LIVE_STATE_ACTIVE, int64(i%4)
		} else {
			t.State, t.GraceUntil = tun.TunLiveState_TUN_LIVE_STATE_GRACE, now+120
		}
		req := relays[i%simRelays]
		req.Tunnels = append(req.Tunnels, t)
		s.TunTunnelIDs = append(s.TunTunnelIDs, t.Name)
	}
	for _, req := range relays {
		req.Relay.Sessions, req.Relay.Tunnels = int32(len(req.Agents)), int32(len(req.Tunnels))
		resp := &tun.TunClaimResponse{}
		if err := post(c, common.AreaLive, common.ClaimService, req, resp); err != nil {
			return err
		}
		if resp.Error != tun.TunClaimError_TUN_CLAIM_ERROR_UNSPECIFIED {
			return fmt.Errorf("announcing %s: %s %s", req.RelayId, resp.Error, resp.Message)
		}
		s.TunRelayIDs = append(s.TunRelayIDs, req.RelayId)
	}
	return nil
}
