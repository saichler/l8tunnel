package common

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"github.com/saichler/l8types/go/types/l8api"
	"github.com/saichler/l8types/go/types/l8events"
	"github.com/saichler/l8types/go/types/l8notify"
)

// RegisterTypes registers every Prime Object (primary-key decorator and
// type registry) and every request/response type of the action services.
// Every process that serves or calls the services calls it: the backend,
// the registry, the relays, the edge and the web UI.
func RegisterTypes(resources ifs.IResources) {
	l8common.RegisterType(resources, &tun.TunToken{}, &tun.TunTokenList{}, "TokenId")
	l8common.RegisterType(resources, &tun.TunReservation{}, &tun.TunReservationList{}, "ReservationId")
	l8common.RegisterType(resources, &tun.TunGatewayKey{}, &tun.TunGatewayKeyList{}, "KeyId")
	l8common.RegisterType(resources, &tun.TunAgentCert{}, &tun.TunAgentCertList{}, "CertId")
	l8common.RegisterType(resources, &tun.EdgeDomain{}, &tun.EdgeDomainList{}, "DomainId")
	l8common.RegisterType(resources, &tun.EdgeNode{}, &tun.EdgeNodeList{}, "EdgeId")
	l8common.RegisterType(resources, &tun.TunRelay{}, &tun.TunRelayList{}, "RelayId")
	l8common.RegisterType(resources, &tun.TunAgent{}, &tun.TunAgentList{}, "AgentId")
	l8common.RegisterType(resources, &tun.TunLiveTunnel{}, &tun.TunLiveTunnelList{}, "Name")
	l8common.RegisterType(resources, &tun.TunAlertRule{}, &tun.TunAlertRuleList{}, "RuleId")

	// Required system services (Events, Notify, IntegCfg; activated by
	// l8common's system.Activate).
	l8common.RegisterType(resources, &l8events.EventRecord{}, &l8events.EventRecordList{}, "EventId")
	l8common.RegisterType(resources, &l8notify.NotifyRecord{}, &l8notify.NotifyRecordList{}, "NotifyId")
	l8common.RegisterType(resources, &l8notify.IntegrationConfig{}, &l8notify.IntegrationConfigList{}, "IntegrationId")

	// Request/response types of the action and listener services. The web
	// process can't route to a service whose endpoint types it can't
	// deserialize, so these are registered everywhere too.
	resources.Registry().Register(&tun.TunIssueRequest{})
	resources.Registry().Register(&tun.TunIssueResponse{})
	resources.Registry().Register(&tun.TunCtlCommand{})
	resources.Registry().Register(&tun.TunClaimRequest{})
	resources.Registry().Register(&tun.TunClaimResponse{})
	resources.Registry().Register(&l8api.L8FileDownloadRequest{})
	resources.Registry().Register(&l8api.L8FileDownloadResponse{})
}
