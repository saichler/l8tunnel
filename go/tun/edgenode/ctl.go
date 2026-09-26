package edgenode

import (
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8utils/go/utils/web"
)

// CtlHandler is the edge's EdgeCtl listener: the backend pushes edge
// domain changes to it.
type CtlHandler struct {
	common.ActionStubs
}

func (n *Node) activateCtl() {
	sla := ifs.NewServiceLevelAgreement(&CtlHandler{}, common.EdgeCtlService, common.AreaEdge, false, nil)
	sla.SetArgs(n)
	sla.SetWebService(web.New(common.EdgeCtlService, common.AreaEdge, 0))
	if _, err := n.vnic.Resources().Services().Activate(sla, n.vnic); err != nil {
		panic("activate " + common.EdgeCtlService + ": " + err.Error())
	}
}

func (h *CtlHandler) Post(e ifs.IElements, _ ifs.IVNic) ifs.IElements   { return h.apply(e) }
func (h *CtlHandler) Put(e ifs.IElements, _ ifs.IVNic) ifs.IElements    { return h.apply(e) }
func (h *CtlHandler) Patch(e ifs.IElements, _ ifs.IVNic) ifs.IElements  { return h.apply(e) }
func (h *CtlHandler) Delete(e ifs.IElements, _ ifs.IVNic) ifs.IElements { return h.apply(e) }

func (h *CtlHandler) apply(elems ifs.IElements) ifs.IElements {
	node := h.Arg(0).(*Node)
	for _, e := range elems.Elements() {
		if _, ok := e.(*tun.EdgeDomain); ok {
			node.reloadSoon()
		}
	}
	return nil
}
