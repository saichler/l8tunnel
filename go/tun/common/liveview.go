package common

import (
	"strings"
	"sync"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

// liveRefetchMin bounds forced refetches of a LiveView.
const liveRefetchMin = time.Second

// LiveView is a cached copy of the registry's live tables, for routing:
// relays use it to forward other relays' tunnels, the edge to route to the
// relay that holds a tunnel. Simulated records are left out.
type LiveView struct {
	vnic ifs.IVNic
	ttl  time.Duration

	mu      sync.Mutex
	byName  map[string]*tun.TunLiveTunnel // active tunnels by name and custom domain
	byPort  map[int32]*tun.TunLiveTunnel
	relays  map[string]*tun.TunRelay
	fetched time.Time
}

// NewLiveView reads the live tables at most every ttl (and on a miss, at
// most once a second).
func NewLiveView(vnic ifs.IVNic, ttl time.Duration) *LiveView {
	return &LiveView{vnic: vnic, ttl: ttl}
}

// Tunnel returns the active tunnel serving host (<name>.<base> or a custom
// domain) and its relay. A miss, or an owner equal to stale (the caller's
// own relay ID, when it knows it doesn't serve the tunnel), refetches once.
func (v *LiveView) Tunnel(host, stale string) (*tun.TunLiveTunnel, *tun.TunRelay) {
	host = strings.ToLower(host)
	key := host
	if name := Cluster().Rules().TunnelName(host); name != "" {
		key = name
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refresh(v.ttl)
	t, r := v.owner(v.byName[key])
	if t == nil || (stale != "" && t.RelayId == stale) {
		v.refresh(liveRefetchMin)
		t, r = v.owner(v.byName[key])
	}
	return t, r
}

// TunnelByPort returns the active tunnel holding a mode A port.
func (v *LiveView) TunnelByPort(port int32) (*tun.TunLiveTunnel, *tun.TunRelay) {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refresh(v.ttl)
	t, r := v.owner(v.byPort[port])
	if t == nil {
		v.refresh(liveRefetchMin)
		t, r = v.owner(v.byPort[port])
	}
	return t, r
}

// Relays lists the relays that are up.
func (v *LiveView) Relays() []*tun.TunRelay {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.refresh(v.ttl)
	out := make([]*tun.TunRelay, 0, len(v.relays))
	for _, r := range v.relays {
		if r.State != tun.TunRelayState_TUN_RELAY_STATE_DOWN {
			out = append(out, r)
		}
	}
	return out
}

// Invalidate makes the next lookup read the tables again.
func (v *LiveView) Invalidate() {
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fetched = time.Time{}
}

func (v *LiveView) owner(t *tun.TunLiveTunnel) (*tun.TunLiveTunnel, *tun.TunRelay) {
	if t == nil {
		return nil, nil
	}
	r := v.relays[t.RelayId]
	if r == nil || r.State == tun.TunRelayState_TUN_RELAY_STATE_DOWN || r.PodIp == "" {
		return nil, nil
	}
	return t, r
}

// refresh reloads the tables when the copy is older than age (callers hold
// v.mu). A failed read keeps the old copy.
func (v *LiveView) refresh(age time.Duration) {
	if time.Since(v.fetched) < age {
		return
	}
	tunnels, err := l8common.GetEntities(LiveService, AreaLive, &tun.TunLiveTunnel{}, v.vnic)
	if err != nil {
		return
	}
	relays, err := l8common.GetEntities(RelayService, AreaLive, &tun.TunRelay{}, v.vnic)
	if err != nil {
		return
	}
	v.byName, v.byPort, v.relays = map[string]*tun.TunLiveTunnel{}, map[int32]*tun.TunLiveTunnel{}, map[string]*tun.TunRelay{}
	for _, e := range tunnels {
		t, ok := e.(*tun.TunLiveTunnel)
		if !ok || t.Name == "" || t.Simulated || t.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			continue
		}
		v.byName[t.Name] = t
		for _, d := range t.Domains {
			v.byName[d] = t
		}
		if t.PublicPort != 0 {
			v.byPort[t.PublicPort] = t
		}
	}
	for _, e := range relays {
		if r, ok := e.(*tun.TunRelay); ok && r.RelayId != "" && !r.Simulated {
			v.relays[r.RelayId] = r
		}
	}
	v.fetched = time.Now()
}
