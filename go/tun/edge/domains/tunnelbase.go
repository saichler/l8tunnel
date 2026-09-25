package domains

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"google.golang.org/protobuf/proto"
)

// tunnelBaseForwards are the TUNNEL_BASE row's port forwards, derived from
// cluster.yaml. They follow the relay configuration, so the UI can't edit
// them.
func tunnelBaseForwards() []*tun.EdgePortForward {
	c := common.Cluster()
	relay := func(id string, port, end int32, proto tun.EdgeProtocol, target int) *tun.EdgePortForward {
		return &tun.EdgePortForward{
			ForwardId: id, ListenPort: port, ListenPortEnd: end, Protocol: proto,
			Mode:       tun.EdgeForwardMode_EDGE_FORWARD_MODE_RELAY,
			TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS, TargetPort: int32(target),
			Lb:         tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN,
			HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_TCP, Enabled: true,
		}
	}
	out := []*tun.EdgePortForward{relay("https", int32(c.Public.HTTPS), 0, tun.EdgeProtocol_EDGE_PROTOCOL_TLS, c.Relay.TLS)}
	if c.Public.HTTP > 0 {
		out = append(out, relay("http", int32(c.Public.HTTP), 0, tun.EdgeProtocol_EDGE_PROTOCOL_HTTP, c.Relay.HTTP))
	}
	lo, hi, _ := protocol.ParsePortRange(c.TCPPortRange) // checked when the config loaded
	end := int32(hi)
	if lo == hi {
		end = 0
	}
	out = append(out, relay("tcp-range", int32(lo), end, tun.EdgeProtocol_EDGE_PROTOCOL_TCP, c.Relay.Stream))
	if c.Public.Gateway > 0 {
		out = append(out, relay("ssh-gateway", int32(c.Public.Gateway), 0, tun.EdgeProtocol_EDGE_PROTOCOL_TCP, c.Relay.Gateway))
	}
	return out
}

// EnsureTunnelBase creates the TUNNEL_BASE row, or brings its port
// forwards in line with cluster.yaml. The backend calls it at startup, and
// again periodically, because a plain ORM DELETE can't be refused.
func EnsureTunnelBase(vnic ifs.IVNic) error {
	all, err := Domains(vnic)
	if err != nil {
		return err
	}
	want := tunnelBaseForwards()
	for _, d := range all {
		if d.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE {
			continue
		}
		if sameForwards(d.PortForwards, want) {
			return nil
		}
		d.PortForwards = want
		return l8common.PutEntity(ServiceName, ServiceArea, d, vnic)
	}
	base := common.Cluster().BaseDomain
	_, err = l8common.PostEntity(ServiceName, ServiceArea, &tun.EdgeDomain{
		Domain:       base,
		Aliases:      []string{"*." + base},
		Kind:         tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE,
		Enabled:      true,
		CertStatus:   tun.EdgeCertStatus_EDGE_CERT_STATUS_MISSING,
		PortForwards: want,
		Note:         "Built in: the relays' ports. Upload the tunnel certificate here.",
	}, vnic)
	return err
}

func sameForwards(a, b []*tun.EdgePortForward) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !proto.Equal(a[i], b[i]) {
			return false
		}
	}
	return true
}
