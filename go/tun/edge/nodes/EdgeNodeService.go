// Package nodes is the EdgeNode service: each running edge's report of its
// listeners and backend health. It is in memory only (no table): a report
// is replaced every few seconds and means nothing after a restart.
package nodes

import (
	"github.com/saichler/l8services/go/services/base"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
	"github.com/saichler/l8types/go/types/l8web"
	"github.com/saichler/l8utils/go/utils/web"
)

const (
	ServiceName = common.EdgeNodeService
	ServiceArea = common.AreaEdge
)

// Activate activates the in-memory service; only the backend calls it
// (SingleOwnerDatabaseTable: one owner process).
func Activate(vnic ifs.IVNic) {
	sla := ifs.NewServiceLevelAgreement(&base.BaseService{}, ServiceName, ServiceArea, true, newEdgeNodeServiceCallback())
	sla.SetServiceItem(&tun.EdgeNode{})
	sla.SetServiceItemList(&tun.EdgeNodeList{})
	sla.SetPrimaryKeys("EdgeId")
	sla.SetVoter(true)
	// Non-transactional, so the UI's realtime tables get the updates.
	sla.SetTransactional(false)

	ws := web.New(ServiceName, ServiceArea, 0)
	ws.AddEndpoint(&tun.EdgeNode{}, ifs.POST, &l8web.L8Empty{})
	ws.AddEndpoint(&tun.EdgeNode{}, ifs.PUT, &l8web.L8Empty{})
	ws.AddEndpoint(&tun.EdgeNode{}, ifs.PATCH, &l8web.L8Empty{})
	ws.AddEndpoint(&l8api.L8Query{}, ifs.DELETE, &l8web.L8Empty{})
	ws.AddEndpoint(&l8api.L8Query{}, ifs.GET, &tun.EdgeNodeList{})
	sla.SetWebService(ws)

	if _, err := base.Activate(sla, vnic); err != nil {
		panic("activate " + ServiceName + ": " + err.Error())
	}
}
