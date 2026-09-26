// Package edgenode runs the edge in the cluster: it feeds the edge
// (tunnel/edge) the edge domains, their certificates and the registry's
// live tables, keeps a cache for when the management plane is down, and
// reports the edge's listeners and backends as its EdgeNode record.
package edgenode

import (
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/edge"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// live adapts the registry's tables to edge.Live.
type live struct {
	view *common.LiveView
}

func target(r *tun.TunRelay) edge.RelayTarget {
	return edge.RelayTarget{ID: r.RelayId, IP: r.PodIp, Sessions: int(r.Sessions),
		Draining: r.State == tun.TunRelayState_TUN_RELAY_STATE_DRAINING}
}

func (l *live) Relays() []edge.RelayTarget {
	var out []edge.RelayTarget
	for _, r := range l.view.Relays() {
		if r.PodIp != "" {
			out = append(out, target(r))
		}
	}
	return out
}

func (l *live) OwnerOfHost(host string) (edge.RelayTarget, bool) {
	_, r := l.view.Tunnel(host, "")
	if r == nil {
		return edge.RelayTarget{}, false
	}
	return target(r), true
}

func (l *live) OwnerOfPort(port int) (edge.RelayTarget, string, bool) {
	t, r := l.view.TunnelByPort(int32(port))
	if t == nil {
		return edge.RelayTarget{}, "", false
	}
	return target(r), t.Name, true
}
