package relaynode

import (
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8utils/go/utils/web"
)

// drainPace spaces out the sessions a draining relay closes.
const drainPace = 200 * time.Millisecond

// CtlHandler is the relay's TunRlyCtl listener: the management backend and
// the registry push changes and commands to it.
type CtlHandler struct {
	common.ActionStubs
}

func (n *Node) activateCtl() {
	sla := ifs.NewServiceLevelAgreement(&CtlHandler{}, common.RelayCtlService, common.AreaLive, false, nil)
	sla.SetArgs(n)
	sla.SetWebService(web.New(common.RelayCtlService, common.AreaLive, 0))
	if _, err := n.vnic.Resources().Services().Activate(sla, n.vnic); err != nil {
		panic("activate " + common.RelayCtlService + ": " + err.Error())
	}
}

func (h *CtlHandler) Post(e ifs.IElements, _ ifs.IVNic) ifs.IElements  { return h.apply(ifs.POST, e) }
func (h *CtlHandler) Put(e ifs.IElements, _ ifs.IVNic) ifs.IElements   { return h.apply(ifs.PUT, e) }
func (h *CtlHandler) Patch(e ifs.IElements, _ ifs.IVNic) ifs.IElements { return h.apply(ifs.PATCH, e) }
func (h *CtlHandler) Delete(e ifs.IElements, _ ifs.IVNic) ifs.IElements {
	return h.apply(ifs.DELETE, e)
}

func (h *CtlHandler) apply(action ifs.Action, elems ifs.IElements) ifs.IElements {
	node := h.Arg(0).(*Node)
	for _, e := range elems.Elements() {
		node.handle(action, e)
	}
	return nil
}

// handle acts on one pushed change or command.
func (n *Node) handle(action ifs.Action, e interface{}) {
	switch v := e.(type) {
	case *tun.TunToken:
		if action == ifs.DELETE {
			n.accounts.dropToken(v.TokenId)
			n.srv.DisconnectToken(v.TokenId)
			return
		}
		n.refreshSoon()
	case *tun.TunAgentCert, *tun.TunGatewayKey:
		n.refreshSoon()
	case *tun.TunLiveTunnel:
		n.link.invalidate() // a tunnel appeared, moved or went away
	case *tun.EdgeDomain:
		if v.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE {
			go n.reloadCert()
		}
	case *tun.TunCtlCommand:
		if v.RelayId != "" && v.RelayId != n.relayID {
			return
		}
		n.command(v)
	}
}

func (n *Node) command(c *tun.TunCtlCommand) {
	switch c.Kind {
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_REANNOUNCE:
		go n.announce()
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DRAIN:
		n.srv.Drain(drainPace)
		go n.heartbeat()
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_RESUME:
		n.srv.Resume()
		go n.heartbeat()
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_AGENT:
		n.srv.DisconnectAgent(c.AgentId, relay.ReasonOperator)
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_TUNNEL:
		n.srv.CloseTunnel(c.TunnelId, relay.ReasonOperator)
	case tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_TAKEN_OVER:
		n.srv.CloseTunnel(c.TunnelId, relay.ReasonTakeover)
	}
}
