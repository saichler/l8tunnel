package mocks

import (
	"fmt"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/types/l8notify"
)

// Phase 5: one alert rule per condition, with email and webhook targets.
func generateAlerts(c *Client, s *MockDataStore, tag string) error {
	if len(s.TunTokenIDs) == 0 {
		return fmt.Errorf("alert rules need the tokens of phase 1")
	}
	rules := []*tun.TunAlertRule{
		{Name: "Relay lost", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST},
		{Name: "No ready relay", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY, CooldownMinutes: 15},
		{Name: "Edge backends down", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_POOL_DOWN},
		{Name: "Certificates expiring", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING, Threshold: 30, CooldownMinutes: 1440},
		{Name: "Edge listener failed", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED},
		{Name: "NAS token offline", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE, Threshold: 60,
			TokenId: s.TunTokenIDs[1]},
		{Name: "Laptop offline", Condition: tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE, Threshold: 30,
			AgentId: agentID(0, tag)},
	}
	for i, r := range rules {
		r.Name += tag
		r.Enabled = i != 4
		r.Targets = []*l8notify.NotifyTarget{
			{Channel: l8notify.NotifyChannel_NOTIFY_CHANNEL_EMAIL, Endpoint: emailTargets[i%len(emailTargets)]},
		}
		if i%2 == 0 {
			r.Targets = append(r.Targets, &l8notify.NotifyTarget{Channel: l8notify.NotifyChannel_NOTIFY_CHANNEL_WEBHOOK,
				Endpoint: webhookTargets[i%len(webhookTargets)]})
		}
		if err := post(c, common.AreaAlerts, common.AlertService, r, nil); err != nil {
			return err
		}
		s.TunAlertIDs = append(s.TunAlertIDs, r.Name)
	}
	return nil
}
