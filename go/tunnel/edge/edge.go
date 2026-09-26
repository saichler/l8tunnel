// Package edge is the reverse proxy and load balancer in front of the
// relays: the only thing the router forwards to. Its listeners come from
// the edge domains' port forwards. It routes each connection by TLS SNI,
// HTTP Host or port: to a site's load-balanced backends (passthrough, or
// TLS terminated with the site's certificate), or to the relays (the one
// that holds a tunnel, the least-loaded one for agents), always passing the
// client's address in a PROXY header. It has no framework dependencies:
// the cluster glue feeds it domains, certificates and the live tables.
package edge

import (
	"errors"
	"log/slog"
	"net/netip"
	"sort"
	"strconv"
	"sync"
	"sync/atomic"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/types/tun"
	"google.golang.org/protobuf/proto"
)

// RelayTarget is a relay the edge can send traffic to.
type RelayTarget struct {
	ID       string
	IP       string
	Sessions int
	Draining bool
}

// Live tells the edge where relays and tunnels are (in the cluster: the
// registry's live tables).
type Live interface {
	// Relays lists the relays that are up (ready or draining).
	Relays() []RelayTarget
	// OwnerOfHost finds the relay serving a tunnel host name or custom
	// domain.
	OwnerOfHost(host string) (RelayTarget, bool)
	// OwnerOfPort finds the relay and tunnel name holding a mode A port.
	OwnerOfPort(port int) (RelayTarget, string, bool)
}

// Config configures an Edge.
type Config struct {
	BaseDomain string
	ControlSNI string
	// NodeIP is the address NODE_LOCAL targets dial.
	NodeIP string
	// BindHost is the address listeners bind; "" means all.
	BindHost string
	// ForwardKey signs mode A streams to the relays.
	ForwardKey []byte
	Live       Live
	// Certs are the TERMINATE sites' certificates.
	Certs *certs.Set
	// ConnectionsPerSecond and ConnectionsBurst limit new connections per
	// client IP; zero means 20 and 100.
	ConnectionsPerSecond float64
	ConnectionsBurst     int
	Logger               *slog.Logger
}

// Edge is the running proxy.
type Edge struct {
	cfg     Config
	log     *slog.Logger
	limiter *auth.IPLimiter

	mu        sync.Mutex
	listeners map[int]*listener
	pools     map[string]*pool // by domain ID + forward ID
	version   int64
	closed    bool

	counters counters
	rr       atomic.Uint64 // round robin over relays
}

type counters struct {
	accepted, rejectedRate, rejectedIP, noRoute, dialFailures atomic.Int64
}

// New validates cfg and returns an edge with no listeners yet.
func New(cfg Config) (*Edge, error) {
	if cfg.BaseDomain == "" || cfg.Live == nil || cfg.Certs == nil {
		return nil, errors.New("edge: BaseDomain, Live and Certs are required")
	}
	if len(cfg.ForwardKey) < 32 {
		return nil, errors.New("edge: the forward key must be at least 32 bytes")
	}
	if cfg.ControlSNI == "" {
		cfg.ControlSNI = "connect." + cfg.BaseDomain
	}
	if cfg.ConnectionsPerSecond == 0 {
		cfg.ConnectionsPerSecond, cfg.ConnectionsBurst = 20, 100
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &Edge{cfg: cfg, log: cfg.Logger, limiter: auth.NewIPLimiter(cfg.ConnectionsPerSecond, cfg.ConnectionsBurst),
		listeners: map[int]*listener{}, pools: map[string]*pool{}}, nil
}

// Apply makes the listeners and pools match the domains: new ports are
// opened, removed ones closed (open connections finish), and unchanged
// pools keep their health state. version is reported back as applied.
func (e *Edge) Apply(domains []*tun.EdgeDomain, version int64) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		return
	}
	pools := map[string]*pool{}
	byPort := map[int][]*route{}
	for _, d := range domains {
		if !d.Enabled {
			continue
		}
		access, err := auth.ParseAccess(accessPolicy(d))
		if err != nil {
			e.log.Warn("edge domain skipped: bad IP lists", "domain", d.Domain, "error", err)
			continue
		}
		for i, f := range d.PortForwards {
			if !f.Enabled {
				continue
			}
			key := d.DomainId + "/" + forwardKey(f, i)
			p := e.pools[key]
			if p == nil || !proto.Equal(p.fwd, f) {
				p = newPool(key, f, e.cfg.NodeIP, e.log)
			}
			pools[key] = p
			r := &route{domain: d, fwd: f, pool: p, access: access}
			if f.Mode == tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE {
				r.tunnel = &poolTunnel{id: key, pool: p, fwd: f, access: access}
			}
			end := f.ListenPortEnd
			if end == 0 {
				end = f.ListenPort
			}
			for port := int(f.ListenPort); port <= int(end); port++ {
				byPort[port] = append(byPort[port], r)
			}
		}
	}
	for key, p := range e.pools {
		if pools[key] != p {
			p.stop()
		}
	}
	e.pools = pools
	for port, l := range e.listeners {
		if routes, ok := byPort[port]; !ok || routes[0].fwd.Protocol != l.proto {
			l.close()
			delete(e.listeners, port)
		}
	}
	for port, routes := range byPort {
		l := e.listeners[port]
		if l == nil {
			l = e.listen(port, routes[0].fwd.Protocol)
			e.listeners[port] = l
		}
		l.setRoutes(newRouteSet(e, routes))
	}
	e.version = version
}

// Close stops every listener and pool.
func (e *Edge) Close() {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	for _, l := range e.listeners {
		l.close()
	}
	for _, p := range e.pools {
		p.stop()
	}
}

func forwardKey(f *tun.EdgePortForward, i int) string {
	if f.ForwardId != "" {
		return f.ForwardId
	}
	return "#" + strconv.Itoa(i)
}

// relayPick chooses a relay: the least-loaded ready one for agents, round
// robin otherwise; draining relays only when nothing else is up.
func (e *Edge) relayPick(leastLoaded bool) (RelayTarget, bool) {
	relays := e.cfg.Live.Relays()
	ready := make([]RelayTarget, 0, len(relays))
	for _, r := range relays {
		if !r.Draining {
			ready = append(ready, r)
		}
	}
	if len(ready) == 0 {
		ready = relays
	}
	if len(ready) == 0 {
		return RelayTarget{}, false
	}
	sort.Slice(ready, func(i, j int) bool { return ready[i].ID < ready[j].ID })
	if leastLoaded {
		best := ready[0]
		for _, r := range ready[1:] {
			if r.Sessions < best.Sessions {
				best = r
			}
		}
		return best, true
	}
	return ready[e.rr.Add(1)%uint64(len(ready))], true
}

func clientIP(addr string) netip.Addr {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}
