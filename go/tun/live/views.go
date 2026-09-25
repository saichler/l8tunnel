// Package live runs in the registry process: it hosts the claims engine
// (tunnel/claims), the TunClaim and TunCtl action services that feed it,
// and the TunLive, TunAgent and TunRelay tables it mirrors its state into
// for the UI. The registry is the single owner of those tables.
package live

import (
	"github.com/saichler/l8services/go/services/base"
	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
	"github.com/saichler/l8utils/go/utils/web"
	"google.golang.org/protobuf/proto"
)

// view is one read-only live table: an in-memory, non-transactional
// service (so the UI's realtime tables get updates). Only the engine writes
// it; clients change live state through TunCtl.
type view struct {
	handler ifs.IServiceHandler
	vnic    ifs.IVNic
}

func activateView(vnic ifs.IVNic, name string, item, list proto.Message, pk string) *view {
	sla := ifs.NewServiceLevelAgreement(&base.BaseService{}, name, common.AreaLive, true, nil)
	sla.SetServiceItem(item)
	sla.SetServiceItemList(list)
	sla.SetPrimaryKeys(pk)
	sla.SetVoter(true)
	sla.SetTransactional(false)
	ws := web.New(name, common.AreaLive, 0)
	ws.AddEndpoint(&l8api.L8Query{}, ifs.GET, list)
	sla.SetWebService(ws)
	h, err := base.Activate(sla, vnic)
	if err != nil {
		panic("activate " + name + ": " + err.Error())
	}
	return &view{handler: h, vnic: vnic}
}

func (v *view) put(elem interface{}) {
	if resp := v.handler.Post(object.New(nil, elem), v.vnic); resp != nil && resp.Error() != nil {
		v.vnic.Resources().Logger().Warning("live table update: ", resp.Error().Error())
	}
}

func (v *view) remove(elem interface{}) {
	if resp := v.handler.Delete(object.New(nil, elem), v.vnic); resp != nil && resp.Error() != nil {
		v.vnic.Resources().Logger().Warning("live table delete: ", resp.Error().Error())
	}
}

// all lists the table's rows.
func (v *view) all() []interface{} {
	cache, ok := v.handler.(ifs.IServiceHandlerCache)
	if !ok {
		return nil
	}
	out := make([]interface{}, 0)
	for _, e := range cache.All() {
		out = append(out, e)
	}
	return out
}

// views are the three live tables.
type views struct {
	tunnels, agents, relays *view
}

func activateViews(vnic ifs.IVNic) *views {
	return &views{
		tunnels: activateView(vnic, common.LiveService, &tun.TunLiveTunnel{}, &tun.TunLiveTunnelList{}, "Name"),
		agents:  activateView(vnic, common.AgentService, &tun.TunAgent{}, &tun.TunAgentList{}, "AgentId"),
		relays:  activateView(vnic, common.RelayService, &tun.TunRelay{}, &tun.TunRelayList{}, "RelayId"),
	}
}
