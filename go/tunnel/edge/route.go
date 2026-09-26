package edge

import (
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// route is one domain's port forward on one listener.
type route struct {
	domain *tun.EdgeDomain
	fwd    *tun.EdgePortForward
	pool   *pool
	access *auth.Access
	tunnel *poolTunnel // TERMINATE only
}

func (r *route) isRelay() bool {
	return r.fwd.Mode == tun.EdgeForwardMode_EDGE_FORWARD_MODE_RELAY
}

// routeSet is everything served on one port.
type routeSet struct {
	edge      *Edge
	byName    map[string]*route // exact site names
	wildcards map[string]*route // ".example.com" -> route
	base      *route            // the tunnel base's forward on this port
	single    *route            // TCP: the port's only route
}

func newRouteSet(e *Edge, routes []*route) *routeSet {
	rs := &routeSet{edge: e, byName: map[string]*route{}, wildcards: map[string]*route{}}
	for _, r := range routes {
		if r.fwd.Protocol == tun.EdgeProtocol_EDGE_PROTOCOL_TCP {
			rs.single = r
		}
		if r.domain.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE {
			rs.base = r
			continue
		}
		for _, n := range append([]string{r.domain.Domain}, r.domain.Aliases...) {
			n = strings.ToLower(n)
			if rest, ok := strings.CutPrefix(n, "*"); ok {
				rs.wildcards[rest] = r
			} else {
				rs.byName[n] = r
			}
		}
	}
	return rs
}

// target is where a resolved connection goes.
type target struct {
	route *route
	// relay is set for relay routes: the chosen relay.
	relay RelayTarget
	ok    bool
}

// resolve picks the route for a host name (SNI or Host):
//  1. an exact site name
//  2. the control name: the least-loaded relay
//  3. a live tunnel (under the base domain, or a tunnel's custom domain):
//     its relay, or any relay when the owner isn't known (it forwards)
//  4. a wildcard site name
//  5. anything else on a tunnel base port: any relay
func (rs *routeSet) resolve(host string) target {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if r := rs.byName[host]; r != nil {
		return target{route: r, ok: true}
	}
	e := rs.edge
	if rs.base != nil && host != "" {
		if host == e.cfg.ControlSNI {
			relay, ok := e.relayPick(true)
			return target{route: rs.base, relay: relay, ok: ok}
		}
		if relay, ok := e.cfg.Live.OwnerOfHost(host); ok {
			return target{route: rs.base, relay: relay, ok: true}
		}
	}
	if i := strings.IndexByte(host, '.'); i > 0 {
		if r := rs.wildcards[host[i:]]; r != nil {
			return target{route: r, ok: true}
		}
	}
	if rs.base != nil {
		relay, ok := e.relayPick(false)
		return target{route: rs.base, relay: relay, ok: ok}
	}
	return target{}
}

func accessPolicy(d *tun.EdgeDomain) *l8tunnel.AccessPolicy {
	return &l8tunnel.AccessPolicy{AllowIps: d.AllowIps, DenyIps: d.DenyIps}
}
