package alerts

import (
	"errors"
	"fmt"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8notify"
)

func newTunAlertServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "TunAlertRule",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.TunAlertRule); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*tun.TunAlertRule).RuleId)
		},
		Validate: validate,
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	r := e.(*tun.TunAlertRule)
	if action == ifs.PATCH {
		return nil, nil // the evaluator only PATCHes last_fired
	}
	if err := l8common.ValidateRequired(r.Name, "Name"); err != nil {
		return nil, err
	}
	switch r.Condition {
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_RELAY_LOST, tun.TunAlertCondition_TUN_ALERT_CONDITION_NO_READY_RELAY,
		tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_POOL_DOWN, tun.TunAlertCondition_TUN_ALERT_CONDITION_EDGE_LISTENER_FAILED:
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_CERT_EXPIRING:
		if r.Threshold < 1 {
			return nil, errors.New("certificate expiry needs a threshold in days")
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_TOKEN_OFFLINE:
		if r.Threshold < 1 {
			return nil, errors.New("token offline needs a threshold in minutes")
		}
		tok, err := tokens.Token(r.TokenId, vnic)
		if err != nil {
			return nil, err
		}
		if tok == nil {
			return nil, fmt.Errorf("token %s doesn't exist", r.TokenId)
		}
	case tun.TunAlertCondition_TUN_ALERT_CONDITION_AGENT_OFFLINE:
		if r.Threshold < 1 || r.AgentId == "" {
			return nil, errors.New("agent offline needs an agent ID and a threshold in minutes")
		}
	default:
		return nil, errors.New("the condition is required")
	}
	if len(r.Targets) == 0 {
		return nil, errors.New("add at least one notification target")
	}
	for _, t := range r.Targets {
		if t.Channel == l8notify.NotifyChannel_NOTIFY_CHANNEL_UNSPECIFIED || t.Endpoint == "" {
			return nil, errors.New("every target needs a channel and an endpoint")
		}
	}
	if r.CooldownMinutes < 0 {
		return nil, errors.New("the cooldown must not be negative")
	}
	if r.CooldownMinutes == 0 {
		r.CooldownMinutes = DefaultCooldownMinutes
	}
	return nil, nil
}
