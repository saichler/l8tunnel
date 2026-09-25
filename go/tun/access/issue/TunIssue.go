// Package issue is the TunIssue action service. It creates tokens and agent
// certificates (returning their secrets exactly once), imports a standalone
// relay's export, and revokes tokens (with their certificates and
// reservations, telling every relay at once). It stores nothing itself:
// secrets never reach the ORM or the event log.
package issue

import (
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8utils/go/utils/web"
)

const (
	ServiceName = common.IssueService
	ServiceArea = common.AreaAccess
)

// IssueHandler serves TunIssue. It isn't named after a proto message: the
// framework's registry creates handlers by bare struct name.
type IssueHandler struct {
	sla *ifs.ServiceLevelAgreement
}

// Activate activates the stateless service; only the backend calls it.
func Activate(vnic ifs.IVNic) {
	sla := ifs.NewServiceLevelAgreement(&IssueHandler{}, ServiceName, ServiceArea, false, nil)
	ws := web.New(ServiceName, ServiceArea, 0)
	ws.AddEndpoint(&tun.TunIssueRequest{}, ifs.POST, &tun.TunIssueResponse{})
	sla.SetWebService(ws)
	if _, err := vnic.Resources().Services().Activate(sla, vnic); err != nil {
		panic("activate " + ServiceName + ": " + err.Error())
	}
}

func (h *IssueHandler) Activate(sla *ifs.ServiceLevelAgreement, _ ifs.IVNic) error {
	h.sla = sla
	return nil
}

func (h *IssueHandler) DeActivate() error {
	return nil
}

func (h *IssueHandler) TransactionConfig() ifs.ITransactionConfig {
	return nil
}

func (h *IssueHandler) WebService() ifs.IWebService {
	return h.sla.WebService()
}
