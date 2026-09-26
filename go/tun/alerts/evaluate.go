package alerts

import (
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// edgeStale is how old an edge's report may be before its listeners and
// pools are no longer judged: an edge that stopped reporting says nothing
// about its backends.
const edgeStale = 2 * time.Minute

// Snapshot is what the evaluator judges the rules against. A source that
// couldn't be read is marked unknown, and the conditions that depend on it
// are skipped rather than fired.
type Snapshot struct {
	Now     time.Time
	LiveOK  bool // Relays and Agents were read
	Relays  []*tun.TunRelay
	Agents  []*tun.TunAgent
	EdgeOK  bool // Nodes and Domains were read
	Nodes   []*tun.EdgeNode
	Domains []*tun.EdgeDomain
}

// Firing is a rule whose condition holds and whose cooldown has passed.
type Firing struct {
	Rule    *tun.TunAlertRule
	Subject string
	Message string
}

// Evaluator judges alert rules. It remembers since when a watched token or
// agent has had no record at all (records expire, and a restarted registry
// only knows the agents that are connected).
type Evaluator struct {
	missingSince map[string]time.Time
}

func NewEvaluator() *Evaluator {
	return &Evaluator{missingSince: map[string]time.Time{}}
}

// Due returns the enabled rules that hold now and are out of their
// cooldown.
func (e *Evaluator) Due(rules []*tun.TunAlertRule, s *Snapshot) []*Firing {
	var out []*Firing
	watched := map[string]bool{}
	for _, r := range rules {
		key := missingKey(r)
		if key != "" {
			watched[key] = true
		}
		if !r.Enabled {
			continue
		}
		items, ok := e.holds(r, s)
		if !ok || len(items) == 0 {
			continue
		}
		cooldown := time.Duration(r.CooldownMinutes) * time.Minute
		if cooldown <= 0 {
			cooldown = DefaultCooldownMinutes * time.Minute
		}
		if r.LastFired != 0 && s.Now.Sub(time.Unix(r.LastFired, 0)) < cooldown {
			continue
		}
		sort.Strings(items)
		out = append(out, &Firing{Rule: r, Subject: "l8tunnel alert: " + r.Name,
			Message: conditionText(r) + ":\n- " + strings.Join(items, "\n- ")})
	}
	for key := range e.missingSince {
		if !watched[key] {
			delete(e.missingSince, key)
		}
	}
	return out
}

// holds returns what matches the rule's condition; ok is false when the
// data it needs is unknown.
func (e *Evaluator) holds(r *tun.TunAlertRule, s *Snapshot) (items []string, ok bool) {
	switch r.Condition {
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST:
		if !s.LiveOK {
			return nil, false
		}
		for _, rl := range s.Relays {
			if !rl.Simulated && rl.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN {
				items = append(items, fmt.Sprintf("relay %s, last seen %s", rl.RelayId, stamp(rl.LastSeen)))
			}
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY:
		if !s.LiveOK {
			return nil, false
		}
		for _, rl := range s.Relays {
			if !rl.Simulated && rl.State == tun.TunRelayState_TUN_RELAY_STATE_READY {
				return nil, true
			}
		}
		items = append(items, fmt.Sprintf("%d relays known, none ready", countReal(s.Relays)))
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_POOL_DOWN:
		if !s.EdgeOK {
			return nil, false
		}
		for _, n := range liveNodes(s) {
			for _, b := range n.Backends {
				if !b.Healthy {
					items = append(items, fmt.Sprintf("edge %s: %s port %d, backend %s down (%s)",
						n.EdgeId, b.Domain, b.ListenPort, b.Target, orNone(b.LastError)))
				}
			}
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED:
		if !s.EdgeOK {
			return nil, false
		}
		for _, n := range liveNodes(s) {
			for _, l := range n.Listeners {
				if !l.Bound {
					items = append(items, fmt.Sprintf("edge %s: port %s for %s: %s",
						n.EdgeId, ports(l), strings.Join(l.Domains, ", "), orNone(l.Error)))
				}
			}
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING:
		if !s.EdgeOK {
			return nil, false
		}
		before := s.Now.Add(time.Duration(r.Threshold) * 24 * time.Hour).Unix()
		for _, d := range s.Domains {
			if d.CertNotAfter != 0 && d.CertNotAfter <= before {
				verb := "expires"
				if d.CertNotAfter <= s.Now.Unix() {
					verb = "expired"
				}
				items = append(items, fmt.Sprintf("%s: the certificate %s %s", d.Domain, verb, stamp(d.CertNotAfter)))
			}
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE:
		if !s.LiveOK {
			return nil, false
		}
		return e.offline(r, s, func(a *tun.TunAgent) bool { return a.TokenId == r.TokenId }, "token "+r.TokenId), true
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE:
		if !s.LiveOK {
			return nil, false
		}
		return e.offline(r, s, func(a *tun.TunAgent) bool { return a.AgentId == r.AgentId }, "agent "+r.AgentId), true
	default:
		return nil, false
	}
	return items, true
}

// offline reports the watched agents when none of them is online and all
// have been gone for longer than the threshold. With no record at all, the
// time is counted from when the evaluator first saw none.
func (e *Evaluator) offline(r *tun.TunAlertRule, s *Snapshot, match func(*tun.TunAgent) bool, what string) []string {
	key := missingKey(r)
	var latest int64
	var names []string
	for _, a := range s.Agents {
		if a.Simulated || !match(a) {
			continue
		}
		if a.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
			delete(e.missingSince, key)
			return nil
		}
		if a.LastSeen > latest {
			latest = a.LastSeen
		}
		names = append(names, a.AgentId)
	}
	limit := time.Duration(r.Threshold) * time.Minute
	if len(names) == 0 {
		since, seen := e.missingSince[key]
		if !seen {
			e.missingSince[key] = s.Now
			return nil
		}
		if s.Now.Sub(since) < limit {
			return nil
		}
		return []string{fmt.Sprintf("%s: no agent connected since at least %s", what, stamp(since.Unix()))}
	}
	delete(e.missingSince, key)
	if s.Now.Sub(time.Unix(latest, 0)) < limit {
		return nil
	}
	return []string{fmt.Sprintf("%s: offline since %s (agents %s)", what, stamp(latest), strings.Join(names, ", "))}
}

func missingKey(r *tun.TunAlertRule) string {
	switch r.Condition {
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE:
		return "token/" + r.TokenId
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE:
		return "agent/" + r.AgentId
	}
	return ""
}

// liveNodes are the real edges that reported recently.
func liveNodes(s *Snapshot) []*tun.EdgeNode {
	var out []*tun.EdgeNode
	for _, n := range s.Nodes {
		if !n.Simulated && s.Now.Sub(time.Unix(n.LastSeen, 0)) <= edgeStale {
			out = append(out, n)
		}
	}
	return out
}

func conditionText(r *tun.TunAlertRule) string {
	switch r.Condition {
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST:
		return "Relays lost"
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY:
		return "No relay is ready"
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_POOL_DOWN:
		return "Edge backends down"
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED:
		return "Edge listeners that couldn't bind"
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING:
		return fmt.Sprintf("Certificates expiring within %d days", r.Threshold)
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE, tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE:
		return fmt.Sprintf("Offline for more than %d minutes", r.Threshold)
	}
	return r.Condition.String()
}

func countReal(relays []*tun.TunRelay) int {
	n := 0
	for _, r := range relays {
		if !r.Simulated {
			n++
		}
	}
	return n
}

func ports(l *tun.EdgeListenerStatus) string {
	if l.PortEnd > l.Port {
		return fmt.Sprintf("%d-%d", l.Port, l.PortEnd)
	}
	return fmt.Sprint(l.Port)
}

func stamp(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format("2006-01-02 15:04 UTC")
}

func orNone(s string) string {
	if s == "" {
		return "no error recorded"
	}
	return s
}
