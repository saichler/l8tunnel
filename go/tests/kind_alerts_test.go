package tests

import (
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/types/l8notify"
)

// notifyArea is l8notify's service area (Notify and IntegCfg).
const notifyArea = byte(78)

// TestKindAlertsFire checks that the backend's evaluator fires rules and
// that the deliveries reach the l8notify delivery log. The webhook target is
// unreachable on purpose: a failed delivery is still recorded.
func TestKindAlertsFire(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	installTunnelCert(t, c) // the TUNNEL_BASE domain has a certificate
	targets := []*l8notify.NotifyTarget{{Channel: l8notify.NotifyChannel_NOTIFY_CHANNEL_WEBHOOK, Endpoint: "http://127.0.0.1:9/l8tunnel-alert"}}

	// A port that can't bind on the edge (the web UI holds 5443 on the node).
	busy := &tun.EdgeDomain{Domain: uniqueName("alert") + ".kind.site", Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{{ForwardId: "busy", ListenPort: 5443, Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
			TargetPort: 1, Enabled: true}}}
	c.mustDo(post, common.AreaEdge, common.DomainService, busy, nil)
	stored := domainsNamed(t, c, busy.Domain)[0]
	t.Cleanup(func() { c.remove(common.AreaEdge, common.DomainService, "EdgeDomain", "domainId="+stored.DomainId) })

	rules := map[string]*tun.TunAlertRule{
		// Every certificate expires within 100 years.
		"cert":     {Name: uniqueName("cert"), Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING, Threshold: 36500},
		"listener": {Name: uniqueName("listener"), Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED},
	}
	ids := map[string]string{}
	for key, r := range rules {
		r.Targets, r.Enabled = targets, true
		c.mustDo(post, common.AreaAlerts, common.AlertService, r, nil)
		list := &tun.TunAlertRuleList{}
		if err := c.query(common.AreaAlerts, common.AlertService, "select * from TunAlertRule where name="+r.Name, list); err != nil || len(list.List) != 1 {
			t.Fatalf("stored rule %s: %v %+v", r.Name, err, list.List)
		}
		ids[key] = list.List[0].RuleId
		id := ids[key]
		t.Cleanup(func() { c.remove(common.AreaAlerts, common.AlertService, "TunAlertRule", "ruleId="+id) })
	}

	// The evaluator runs every 30 s, after a minute's grace at backend start.
	want := map[string]string{"cert": kindBase, "listener": "port 5443 for " + busy.Domain}
	records := map[string]*l8notify.NotifyRecord{}
	waitUntil(t, 150*time.Second, "alerts delivered", func() bool {
		list := &l8notify.NotifyRecordList{}
		if err := c.query(notifyArea, "Notify", "select * from NotifyRecord", list); err != nil {
			return false
		}
		for _, rec := range list.List {
			for key, id := range ids {
				if rec.Attributes["ruleId"] == id {
					records[key] = rec
				}
			}
		}
		return len(records) == len(ids)
	})
	for key, rec := range records {
		if rec.Subject != "l8tunnel alert: "+rules[key].Name || !strings.Contains(rec.Message, want[key]) {
			t.Errorf("%s alert: subject %q message %q", key, rec.Subject, rec.Message)
		}
		if rec.Channel != l8notify.NotifyChannel_NOTIFY_CHANNEL_WEBHOOK || rec.Status != l8notify.DeliveryStatus_DELIVERY_STATUS_FAILED {
			t.Errorf("%s alert: channel %s status %s", key, rec.Channel, rec.Status)
		}
	}

	// Firing stamps last_fired, which starts the cooldown: no second record.
	for key, id := range ids {
		list := &tun.TunAlertRuleList{}
		if err := c.query(common.AreaAlerts, common.AlertService, "select * from TunAlertRule where ruleId="+id, list); err != nil || len(list.List) != 1 {
			t.Fatalf("rule %s: %v", key, err)
		}
		if r := list.List[0]; r.LastFired == 0 || r.CooldownMinutes != 60 || len(r.Targets) != 1 {
			t.Errorf("%s rule after firing: %+v", key, r)
		}
	}
	time.Sleep(35 * time.Second) // one more evaluation
	list := &l8notify.NotifyRecordList{}
	if err := c.query(notifyArea, "Notify", "select * from NotifyRecord", list); err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, rec := range list.List {
		for key, id := range ids {
			if rec.Attributes["ruleId"] == id {
				counts[key]++
			}
		}
	}
	for key, n := range counts {
		if n != 1 {
			t.Errorf("%s fired %d times inside its cooldown", key, n)
		}
	}
}
