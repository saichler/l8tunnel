package live

import (
	"github.com/saichler/l8srlz/go/serialize/object"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/claims"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8utils/go/utils/web"
	"google.golang.org/protobuf/proto"
)

// ClaimHandler serves TunClaim: every relay request goes to the engine. A
// claim first reloads the reservations and site names, so a reservation
// made a moment ago is honored at once.
type ClaimHandler struct {
	common.ActionStubs
}

func (h *ClaimHandler) Post(elems ifs.IElements, vnic ifs.IVNic) ifs.IElements {
	req, ok := elems.Element().(*tun.TunClaimRequest)
	if !ok {
		return object.NewError("invalid TunClaimRequest")
	}
	if req.Kind == tun.TunClaimKind_TUN_CLAIM_KIND_CLAIM {
		h.Arg(1).(*directory).refreshForClaim(vnic)
	}
	return object.New(nil, h.Arg(0).(*claims.Engine).Handle(req))
}

// CtlHandler serves TunCtl: an operator's disconnect, drain or resume.
type CtlHandler struct {
	common.ActionStubs
}

func (h *CtlHandler) Post(elems ifs.IElements, _ ifs.IVNic) ifs.IElements {
	cmd, ok := elems.Element().(*tun.TunCtlCommand)
	if !ok {
		return object.NewError("invalid TunCtlCommand")
	}
	if err := h.Arg(0).(*claims.Engine).Command(cmd); err != nil {
		return object.NewError(err.Error())
	}
	return object.New(nil, cmd)
}

func activateAction(vnic ifs.IVNic, handler ifs.IServiceHandler, engine *claims.Engine, dir *directory, name string, req, resp proto.Message) {
	sla := ifs.NewServiceLevelAgreement(handler, name, common.AreaLive, false, nil)
	sla.SetArgs(engine, dir)
	ws := web.New(name, common.AreaLive, 0)
	ws.AddEndpoint(req, ifs.POST, resp)
	sla.SetWebService(ws)
	if _, err := vnic.Resources().Services().Activate(sla, vnic); err != nil {
		panic("activate " + name + ": " + err.Error())
	}
}
