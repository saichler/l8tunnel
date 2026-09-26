package tests

import (
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/claims"
	"github.com/saichler/l8tunnel/go/tunnel/registry"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// recordingSink keeps the engine's latest view and its commands.
type recordingSink struct {
	mu       sync.Mutex
	tunnels  map[string]*tun.TunLiveTunnel
	agents   map[string]*tun.TunAgent
	relays   map[string]*tun.TunRelay
	commands []*tun.TunCtlCommand
}

func newRecordingSink() *recordingSink {
	return &recordingSink{tunnels: map[string]*tun.TunLiveTunnel{}, agents: map[string]*tun.TunAgent{}, relays: map[string]*tun.TunRelay{}}
}

func (s *recordingSink) TunnelChanged(r *tun.TunLiveTunnel, change claims.Change) {
	deleted := change == claims.Deleted
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.tunnels, r.Name)
	} else {
		s.tunnels[r.Name] = r
	}
}

func (s *recordingSink) AgentChanged(r *tun.TunAgent, change claims.Change) {
	deleted := change == claims.Deleted
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.agents, r.AgentId)
	} else {
		s.agents[r.AgentId] = r
	}
}

func (s *recordingSink) RelayChanged(r *tun.TunRelay, change claims.Change) {
	deleted := change == claims.Deleted
	s.mu.Lock()
	defer s.mu.Unlock()
	if deleted {
		delete(s.relays, r.RelayId)
	} else {
		s.relays[r.RelayId] = r
	}
}

func (s *recordingSink) Command(c *tun.TunCtlCommand) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.commands = append(s.commands, c)
}

type staticDirectory struct {
	reservations []*tun.TunReservation
	sites        map[string]bool
}

func (d *staticDirectory) Reservations() []*tun.TunReservation { return d.reservations }
func (d *staticDirectory) IsSiteName(host string) bool         { return d.sites[host] }

type fakeClock struct{ t time.Time }

func (c *fakeClock) now() time.Time      { return c.t }
func (c *fakeClock) add(d time.Duration) { c.t = c.t.Add(d) }

func newEngine(dir *staticDirectory) (*claims.Engine, *recordingSink, *fakeClock) {
	sink, clock := newRecordingSink(), &fakeClock{t: time.Unix(1_800_000_000, 0)}
	e := claims.New(claims.Config{
		Rules: registry.Rules{BaseDomain: baseDomain, ControlSNI: controlSNI, ReservedNames: []string{"www"}, PortMin: 22000, PortMax: 22009},
		Now:   clock.now,
	}, dir, sink)
	return e, sink, clock
}

func claimReq(relay, session, agent, token string, tunnels ...*tun.TunLiveTunnel) *tun.TunClaimRequest {
	return &tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_CLAIM, RelayId: relay, SessionId: session,
		AgentId: agent, TokenId: token, Tunnels: tunnels}
}

func sshTunnel(name string, port int32) *tun.TunLiveTunnel {
	return &tun.TunLiveTunnel{TunnelId: "id-" + name, Name: name, Type: tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH, PublicPort: port}
}

func httpTunnel(name string, domains ...string) *tun.TunLiveTunnel {
	return &tun.TunLiveTunnel{TunnelId: "id-" + name, Name: name, Type: tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP, Domains: domains}
}

func expectClaimError(t *testing.T, resp *tun.TunClaimResponse, code tun.TunClaimError, what string) {
	t.Helper()
	if resp.Error != code {
		t.Errorf("%s: error %s (%q), want %s", what, resp.Error, resp.Message, code)
	}
}

func TestClaimsEngineClaimsAndPorts(t *testing.T) {
	dir := &staticDirectory{reservations: []*tun.TunReservation{{Name: "kept", TokenId: "tokB", PublicPort: 22000}},
		sites: map[string]bool{"admin." + baseDomain: true}}
	e, sink, _ := newEngine(dir)

	resp := e.Handle(claimReq("relay-0", "s1", "agentA", "tokA", sshTunnel("box", 0), httpTunnel("web", "app.custom.test")))
	if resp.Error != 0 || len(resp.Tunnels) != 2 {
		t.Fatalf("claim: %+v", resp)
	}
	// 22000 is reserved for "kept", so the lowest free port is 22001.
	if resp.Tunnels[0].PublicPort != 22001 || resp.Tunnels[0].State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE || resp.Tunnels[1].PublicPort != 0 {
		t.Fatalf("claimed records %+v", resp.Tunnels)
	}
	if sink.tunnels["box"].RelayId != "relay-0" {
		t.Fatal("the sink didn't see the claim")
	}

	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", sshTunnel("box", 0))), tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "another token's name")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", sshTunnel("other", 22001))), tun.TunClaimError_TUN_CLAIM_ERROR_PORT_UNAVAILABLE, "a held port")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", sshTunnel("other", 30000))), tun.TunClaimError_TUN_CLAIM_ERROR_PORT_NOT_ALLOWED, "a port outside the range")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokA", sshTunnel("kept", 0))), tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "another token's reservation")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", httpTunnel("site2", "app.custom.test"))), tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "a held domain")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", httpTunnel("admin"))), tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "an edge site's name")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", httpTunnel("www"))), tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "a reserved name")
	expectClaimError(t, e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", httpTunnel("Bad_Name"))), tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "an invalid name")

	// The reservation's owner gets its reserved port.
	resp = e.Handle(claimReq("relay-1", "s2", "agentB", "tokB", sshTunnel("kept", 0)))
	if resp.Error != 0 || resp.Tunnels[0].PublicPort != 22000 {
		t.Fatalf("reserved port: %+v", resp)
	}

	// All or nothing: one bad tunnel refuses the whole request.
	resp = e.Handle(claimReq("relay-1", "s3", "agentC", "tokC", sshTunnel("fine", 0), sshTunnel("box", 0)))
	expectClaimError(t, resp, tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "one bad tunnel")
	if sink.tunnels["fine"] != nil {
		t.Fatal("a refused request claimed a tunnel")
	}

	// max tunnels counts the token's tunnels across relays.
	req := claimReq("relay-1", "s4", "agentD", "tokA", httpTunnel("third"))
	req.MaxTunnels = 2
	expectClaimError(t, e.Handle(req), tun.TunClaimError_TUN_CLAIM_ERROR_MAX_TUNNELS, "max tunnels")
}

func TestClaimsEngineTakeoverGraceAndLostRelay(t *testing.T) {
	e, sink, clock := newEngine(&staticDirectory{})
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_HEARTBEAT, RelayId: "relay-0"})
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_UP, RelayId: "relay-0",
		Agent: &tun.TunAgent{AgentId: "agentA", SessionId: "s1", TokenId: "tokA", Version: "1.2"}})
	first := e.Handle(claimReq("relay-0", "s1", "agentA", "tokA", sshTunnel("box", 0)))
	port := first.Tunnels[0].PublicPort

	// The same agent reconnects through relay-1 before relay-0 noticed:
	// takeover, same port, and relay-0 is told to close the old tunnel.
	resp := e.Handle(claimReq("relay-1", "s2", "agentA", "tokA", sshTunnel("box", 0)))
	if resp.Error != 0 || resp.Tunnels[0].RelayId != "relay-1" || resp.Tunnels[0].PublicPort != port {
		t.Fatalf("takeover: %+v", resp)
	}
	if len(sink.commands) != 1 || sink.commands[0].Kind != tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_TAKEN_OVER || sink.commands[0].RelayId != "relay-0" {
		t.Fatalf("takeover command %+v", sink.commands)
	}
	// A park from the old relay doesn't touch the new owner's tunnel.
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_PARK, RelayId: "relay-0", SessionId: "s1", Names: []string{"box"}})
	if sink.tunnels["box"].State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
		t.Fatal("a stale park parked the new owner's tunnel")
	}

	// relay-1 parks it; within the grace period only the token can claim it.
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_PARK, RelayId: "relay-1", SessionId: "s2", Names: []string{"box"}})
	if sink.tunnels["box"].State != tun.TunLiveState_TUN_LIVE_STATE_GRACE {
		t.Fatalf("park: %+v", sink.tunnels["box"])
	}
	expectClaimError(t, e.Handle(claimReq("relay-0", "s9", "agentZ", "tokZ", sshTunnel("box", 0))), tun.TunClaimError_TUN_CLAIM_ERROR_NAME_TAKEN, "a parked name")
	resp = e.Handle(claimReq("relay-0", "s3", "agentA2", "tokA", sshTunnel("box", 0)))
	if resp.Error != 0 || resp.Tunnels[0].PublicPort != port {
		t.Fatalf("reclaim by the token: %+v", resp)
	}

	// relay-0 goes silent: it is lost, its tunnels parked, its agents in grace.
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_UP, RelayId: "relay-0",
		Agent: &tun.TunAgent{AgentId: "agentA2", SessionId: "s3", TokenId: "tokA"}})
	clock.add(claims.DefaultRelayTimeout + time.Second)
	e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_HEARTBEAT, RelayId: "relay-1"})
	e.Sweep()
	if sink.relays["relay-0"].State != tun.TunRelayState_TUN_RELAY_STATE_DOWN || sink.relays["relay-1"].State != tun.TunRelayState_TUN_RELAY_STATE_READY {
		t.Fatalf("relay states %v / %v", sink.relays["relay-0"].State, sink.relays["relay-1"].State)
	}
	if sink.tunnels["box"].State != tun.TunLiveState_TUN_LIVE_STATE_GRACE ||
		sink.agents["agentA2"].State != tun.TunAgentState_TUN_AGENT_STATE_GRACE ||
		sink.agents["agentA2"].DisconnectReason != tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_LOST {
		t.Fatalf("after relay loss: %+v %+v", sink.tunnels["box"], sink.agents["agentA2"])
	}
	// After the grace period the name is free and the agent offline; after
	// the retention the agent record goes.
	clock.add(claims.DefaultGrace + time.Second)
	e.Sweep()
	if sink.tunnels["box"] != nil || sink.agents["agentA2"].State != tun.TunAgentState_TUN_AGENT_STATE_OFFLINE {
		t.Fatalf("after the grace period: %+v %+v", sink.tunnels["box"], sink.agents["agentA2"])
	}
	clock.add(claims.DefaultOfflineRetention + time.Second)
	e.Sweep()
	if sink.agents["agentA2"] != nil || sink.relays["relay-0"] != nil {
		t.Fatal("offline agent or lost relay kept past retention")
	}
}

func TestClaimsEngineAnnounceAndCommands(t *testing.T) {
	e, sink, _ := newEngine(&staticDirectory{})
	e.Handle(claimReq("relay-0", "s1", "agentA", "tokA", httpTunnel("web")))
	// A restarted relay-1 announces a tunnel relay-0 now holds for another
	// agent: that is a conflict relay-1 must close.
	resp := e.Handle(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE, RelayId: "relay-1",
		Relay:   &tun.TunRelay{PodIp: "10.0.0.2"},
		Tunnels: []*tun.TunLiveTunnel{{Name: "web", AgentId: "agentB", TokenId: "tokA"}, {Name: "api", AgentId: "agentB", TokenId: "tokA"}}})
	if len(resp.Conflicts) != 1 || resp.Conflicts[0] != "web" || sink.tunnels["api"].RelayId != "relay-1" {
		t.Fatalf("announce: %+v", resp)
	}

	if err := e.Command(&tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DRAIN, RelayId: "relay-1"}); err != nil {
		t.Fatal(err)
	}
	if sink.relays["relay-1"].State != tun.TunRelayState_TUN_RELAY_STATE_DRAINING {
		t.Fatal("drain didn't mark the relay")
	}
	cmd := &tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_TUNNEL, TunnelId: "id-web"}
	if err := e.Command(cmd); err != nil || cmd.RelayId != "relay-0" {
		t.Fatalf("disconnect tunnel routed to %q: %v", cmd.RelayId, err)
	}
	if err := e.Command(&tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_AGENT, AgentId: "nobody"}); !errors.Is(err, claims.ErrNotFound) {
		t.Fatalf("disconnecting an unknown agent: %v", err)
	}
	// Simulated records are refused unless the engine allows them.
	resp = e.Handle(claimReq("demo-relay", "s", "a", "t", &tun.TunLiveTunnel{Name: "demo-x", Type: tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP, Simulated: true}))
	if resp.Error != tun.TunClaimError_TUN_CLAIM_ERROR_FORBIDDEN || !strings.Contains(resp.Message, "simulated") {
		t.Fatalf("simulated claim: %+v", resp)
	}
}
