package alerts

import (
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8events"
	"github.com/saichler/l8types/go/types/l8notify"
	"google.golang.org/protobuf/proto"
)

const (
	// evaluateInterval is how often the rules are judged. Layer 8 has no
	// change subscription for services another process owns (§16.2), and the
	// *_OFFLINE conditions are about time anyway, so the evaluator reads the
	// tables on a timer.
	evaluateInterval = 30 * time.Second
	// startupGrace lets relays and edges report after a cluster start before
	// NO_READY_RELAY and the edge conditions are judged.
	startupGrace = time.Minute
)

// StartEvaluator judges the alert rules every 30 s in the backend and
// notifies each firing rule's targets through l8notify.
func StartEvaluator(vnic ifs.IVNic) {
	go func() {
		time.Sleep(startupGrace)
		e := NewEvaluator()
		for {
			e.round(vnic)
			time.Sleep(evaluateInterval)
		}
	}()
}

func (e *Evaluator) round(vnic ifs.IVNic) {
	log := vnic.Resources().Logger()
	rules, err := Rules(vnic)
	if err != nil {
		log.Warning("alerts: can't read the rules: ", err.Error())
		return
	}
	if len(rules) == 0 {
		return
	}
	for _, f := range e.Due(rules, snapshot(vnic)) {
		fire(f, vnic)
	}
}

// snapshot reads the live and edge tables; a source that fails is marked
// unknown.
func snapshot(vnic ifs.IVNic) *Snapshot {
	s := &Snapshot{Now: time.Now()}
	relays, err1 := l8common.GetEntities(common.RelayService, common.AreaLive, &tun.TunRelay{}, vnic)
	agents, err2 := l8common.GetEntities(common.AgentService, common.AreaLive, &tun.TunAgent{}, vnic)
	if err1 == nil && err2 == nil {
		s.LiveOK = true
		for _, r := range relays {
			if rl, ok := r.(*tun.TunRelay); ok && rl.RelayId != "" {
				s.Relays = append(s.Relays, rl)
			}
		}
		for _, a := range agents {
			if ag, ok := a.(*tun.TunAgent); ok && ag.AgentId != "" {
				s.Agents = append(s.Agents, ag)
			}
		}
	}
	nodes, err1 := l8common.GetEntities(common.EdgeNodeService, common.AreaEdge, &tun.EdgeNode{}, vnic)
	all, err2 := domains.Domains(vnic)
	if err1 == nil && err2 == nil {
		s.EdgeOK = true
		s.Domains = all
		for _, n := range nodes {
			if node, ok := n.(*tun.EdgeNode); ok && node.EdgeId != "" {
				s.Nodes = append(s.Nodes, node)
			}
		}
	}
	return s
}

// fire notifies every target, records the alert as an event and stamps the
// rule's last_fired, which starts its cooldown.
func fire(f *Firing, vnic ifs.IVNic) {
	r := f.Rule
	attrs := map[string]string{"ruleId": r.RuleId, "condition": r.Condition.String()}
	if n := vnic.Resources().Notify(); n != nil {
		for _, t := range r.Targets {
			if res := n.Send(t.Channel, t.Endpoint, f.Subject, f.Message, attrs); res.Status != l8notify.DeliveryStatus_DELIVERY_STATUS_SENT {
				vnic.Resources().Logger().Warning("alerts: ", r.Name, " to ", t.Endpoint, ": ", res.Status.String(), " ", res.ErrorMessage)
			}
		}
	} else {
		vnic.Resources().Logger().Warning("alerts: no notify service; alert ", r.Name, " not delivered")
	}
	common.PostEvent(vnic, l8events.EventCategory_EVENT_CATEGORY_SYSTEM, "alert.fired", l8events.Severity_SEVERITY_WARNING,
		r.RuleId, r.Name, f.Message, attrs)
	stamped := proto.Clone(r).(*tun.TunAlertRule)
	stamped.LastFired = time.Now().Unix()
	if err := common.PatchEntity(ServiceName, ServiceArea, stamped, vnic); err != nil {
		vnic.Resources().Logger().Warning("alerts: can't record the firing of ", r.Name, ": ", err.Error())
	}
}
