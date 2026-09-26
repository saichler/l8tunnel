package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/alerts"
	"github.com/saichler/l8tunnel/go/types/tun"
)

func alertRule(cond tun.TunAlertCondition, threshold int32) *tun.TunAlertRule {
	return &tun.TunAlertRule{RuleId: "r", Name: "rule", Condition: cond, Threshold: threshold, CooldownMinutes: 60, Enabled: true}
}

// due runs one evaluation of a single rule and returns its message, or ""
// when it didn't fire.
func due(e *alerts.Evaluator, r *tun.TunAlertRule, s *alerts.Snapshot) string {
	for _, f := range e.Due([]*tun.TunAlertRule{r}, s) {
		return f.Message
	}
	return ""
}

func TestAlertRelayConditions(t *testing.T) {
	now := time.Now()
	ready := &tun.TunRelay{RelayId: "relay-0", State: tun.TunRelayState_TUN_RELAY_STATE_READY}
	down := &tun.TunRelay{RelayId: "relay-1", State: tun.TunRelayState_TUN_RELAY_STATE_DOWN, LastSeen: now.Add(-time.Minute).Unix()}
	simDown := &tun.TunRelay{RelayId: "sim", State: tun.TunRelayState_TUN_RELAY_STATE_DOWN, Simulated: true}
	draining := &tun.TunRelay{RelayId: "relay-2", State: tun.TunRelayState_TUN_RELAY_STATE_DRAINING}
	simReady := &tun.TunRelay{RelayId: "sim-ready", State: tun.TunRelayState_TUN_RELAY_STATE_READY, Simulated: true}
	e := alerts.NewEvaluator()
	lost := alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST, 0)

	if msg := due(e, lost, &alerts.Snapshot{Now: now, LiveOK: true, Relays: []*tun.TunRelay{ready, down, simDown}}); !strings.Contains(msg, "relay-1") || strings.Contains(msg, "sim") {
		t.Fatalf("relay lost: %q", msg)
	}
	if msg := due(e, lost, &alerts.Snapshot{Now: now, LiveOK: true, Relays: []*tun.TunRelay{ready, simDown}}); msg != "" {
		t.Fatalf("a simulated relay fired: %q", msg)
	}
	if msg := due(e, lost, &alerts.Snapshot{Now: now}); msg != "" {
		t.Fatalf("fired on unknown live tables: %q", msg)
	}

	none := alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY, 0)
	if msg := due(e, none, &alerts.Snapshot{Now: now, LiveOK: true, Relays: []*tun.TunRelay{draining, down, simReady}}); !strings.Contains(msg, "2 relays known, none ready") {
		t.Fatalf("no ready relay: %q", msg)
	}
	if msg := due(e, none, &alerts.Snapshot{Now: now, LiveOK: true, Relays: []*tun.TunRelay{draining, ready}}); msg != "" {
		t.Fatalf("fired with a ready relay: %q", msg)
	}
	if msg := due(e, none, &alerts.Snapshot{Now: now, LiveOK: true}); msg == "" {
		t.Fatal("no relays at all didn't fire")
	}
}

func TestAlertEdgeConditions(t *testing.T) {
	now := time.Now()
	live := &tun.EdgeNode{EdgeId: "edge-a", LastSeen: now.Unix(),
		Listeners: []*tun.EdgeListenerStatus{{Port: 443, Bound: true}, {Port: 5443, Error: "address already in use", Domains: []string{"busy.test"}}},
		Backends: []*tun.EdgeBackendStatus{{Domain: "s/f", ListenPort: 443, Target: "10.0.0.1:80", Healthy: true},
			{Domain: "s/f", ListenPort: 443, Target: "10.0.0.2:80", LastError: "connection refused"}}}
	stale := &tun.EdgeNode{EdgeId: "edge-old", LastSeen: now.Add(-10 * time.Minute).Unix(),
		Listeners: []*tun.EdgeListenerStatus{{Port: 6000}}, Backends: []*tun.EdgeBackendStatus{{Target: "10.0.0.3:80"}}}
	s := &alerts.Snapshot{Now: now, EdgeOK: true, Nodes: []*tun.EdgeNode{live, stale}}
	e := alerts.NewEvaluator()

	msg := due(e, alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED, 0), s)
	if !strings.Contains(msg, "edge-a: port 5443 for busy.test: address already in use") || strings.Contains(msg, "port 443 ") || strings.Contains(msg, "edge-old") {
		t.Fatalf("listener failed: %q", msg)
	}
	msg = due(e, alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_POOL_DOWN, 0), s)
	if !strings.Contains(msg, "10.0.0.2:80 down (connection refused)") || strings.Contains(msg, "10.0.0.1") || strings.Contains(msg, "10.0.0.3") {
		t.Fatalf("pool down: %q", msg)
	}

	certs := &alerts.Snapshot{Now: now, EdgeOK: true, Domains: []*tun.EdgeDomain{
		{Domain: "soon.test", CertNotAfter: now.Add(10 * 24 * time.Hour).Unix()},
		{Domain: "gone.test", CertNotAfter: now.Add(-time.Hour).Unix()},
		{Domain: "later.test", CertNotAfter: now.Add(90 * 24 * time.Hour).Unix()},
		{Domain: "nocert.test"}}}
	msg = due(e, alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING, 30), certs)
	if !strings.Contains(msg, "soon.test: the certificate expires") || !strings.Contains(msg, "gone.test: the certificate expired") ||
		strings.Contains(msg, "later.test") || strings.Contains(msg, "nocert.test") {
		t.Fatalf("cert expiring: %q", msg)
	}
	if msg := due(e, alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING, 5), &alerts.Snapshot{Now: now, EdgeOK: true,
		Domains: certs.Domains[:1]}); msg != "" {
		t.Fatalf("a certificate outside the threshold fired: %q", msg)
	}
}

func TestAlertOfflineConditions(t *testing.T) {
	now := time.Now()
	agentRule := alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE, 5)
	agentRule.AgentId = "laptop"
	offline := func(minutes int) *tun.TunAgent {
		return &tun.TunAgent{AgentId: "laptop", TokenId: "tok", State: tun.TunAgentState_TUN_AGENT_STATE_OFFLINE,
			LastSeen: now.Add(-time.Duration(minutes) * time.Minute).Unix()}
	}
	e := alerts.NewEvaluator()
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now, LiveOK: true, Agents: []*tun.TunAgent{offline(10)}}); !strings.Contains(msg, "agent laptop: offline since") {
		t.Fatalf("agent offline: %q", msg)
	}
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now, LiveOK: true, Agents: []*tun.TunAgent{offline(2)}}); msg != "" {
		t.Fatalf("fired inside the threshold: %q", msg)
	}

	// No record at all: counted from the first evaluation that saw none.
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now, LiveOK: true}); msg != "" {
		t.Fatalf("a missing record fired at once: %q", msg)
	}
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now.Add(6 * time.Minute), LiveOK: true}); !strings.Contains(msg, "no agent connected since") {
		t.Fatalf("missing record past the threshold: %q", msg)
	}
	// The agent comes back, then goes missing again: the count restarts.
	online := &tun.TunAgent{AgentId: "laptop", TokenId: "tok", State: tun.TunAgentState_TUN_AGENT_STATE_ONLINE}
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now.Add(7 * time.Minute), LiveOK: true, Agents: []*tun.TunAgent{online}}); msg != "" {
		t.Fatalf("fired while online: %q", msg)
	}
	if msg := due(e, agentRule, &alerts.Snapshot{Now: now.Add(8 * time.Minute), LiveOK: true}); msg != "" {
		t.Fatalf("the missing count didn't restart: %q", msg)
	}

	tokenRule := alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE, 5)
	tokenRule.TokenId = "tok"
	other := &tun.TunAgent{AgentId: "desktop", TokenId: "tok", State: tun.TunAgentState_TUN_AGENT_STATE_ONLINE}
	if msg := due(e, tokenRule, &alerts.Snapshot{Now: now, LiveOK: true, Agents: []*tun.TunAgent{offline(30), other}}); msg != "" {
		t.Fatalf("token offline fired with one agent online: %q", msg)
	}
	other.State, other.LastSeen = tun.TunAgentState_TUN_AGENT_STATE_GRACE, now.Add(-20*time.Minute).Unix()
	if msg := due(e, tokenRule, &alerts.Snapshot{Now: now, LiveOK: true, Agents: []*tun.TunAgent{offline(30), other}}); !strings.Contains(msg, "token tok: offline since") {
		t.Fatalf("token offline: %q", msg)
	}
	if msg := due(e, tokenRule, &alerts.Snapshot{Now: now}); msg != "" {
		t.Fatalf("fired on unknown live tables: %q", msg)
	}
}

func TestAlertCooldownAndDisabled(t *testing.T) {
	now := time.Now()
	s := &alerts.Snapshot{Now: now, LiveOK: true}
	r := alertRule(tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY, 0)
	e := alerts.NewEvaluator()
	fs := e.Due([]*tun.TunAlertRule{r}, s)
	if len(fs) != 1 || fs[0].Subject != "l8tunnel alert: rule" {
		t.Fatalf("first firing: %+v", fs)
	}
	r.LastFired = now.Add(-30 * time.Minute).Unix()
	if msg := due(e, r, s); msg != "" {
		t.Fatal("fired inside the cooldown")
	}
	r.LastFired = now.Add(-61 * time.Minute).Unix()
	if msg := due(e, r, s); msg == "" {
		t.Fatal("didn't fire after the cooldown")
	}
	r.LastFired, r.Enabled = 0, false
	if msg := due(e, r, s); msg != "" {
		t.Fatal("a disabled rule fired")
	}
}
