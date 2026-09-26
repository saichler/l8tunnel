// Package alerts is the TunAlert service: alert rules whose targets are
// notified (through l8notify) when a condition holds, judged by the
// backend's evaluator.
package alerts

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.AlertService
	ServiceArea = common.AreaAlerts
)

// DefaultCooldownMinutes is a rule's cooldown when none is given.
const DefaultCooldownMinutes = 60

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "RuleId", newTunAlertServiceCallback(),
		&tun.TunAlertRule{}, &tun.TunAlertRuleList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Rules returns every alert rule.
func Rules(vnic ifs.IVNic) ([]*tun.TunAlertRule, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.TunAlertRule{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.TunAlertRule, 0, len(elems))
	for _, e := range elems {
		if r, ok := e.(*tun.TunAlertRule); ok && r.RuleId != "" {
			out = append(out, r)
		}
	}
	return out, nil
}
