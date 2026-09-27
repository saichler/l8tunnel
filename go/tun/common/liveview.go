package common

import (
	"strings"
	"sync"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	// liveRefetchMin bounds forced refetches of a LiveView, and is how long
	// a failed fetch is backed off.
	liveRefetchMin = time.Second
	// liveMissWait is how long a lookup that misses (or finds no copy at
	// all) waits for the refresh it started; everything else answers from
	// the current copy at once.
	liveMissWait = 2 * time.Second
)

// LiveView is a cached copy of the registry's live tables, for routing:
// relays use it to forward other relays' tunnels, the edge to route to the
// relay that holds a tunnel. Simulated records are left out.
//
// Lookups never hold the lock while the registry is asked: a copy older
// than ttl is refreshed in the background (one fetch at a time) while the
// lookup answers from it, and only a miss waits for the refresh, at most
// liveMissWait. When the registry doesn't answer, the last copy keeps
// serving and the fetch is retried after liveRefetchMin.
type LiveView struct {
	vnic ifs.IVNic
	ttl  time.Duration

	mu       sync.Mutex
	byName   map[string]*tun.TunLiveTunnel // active tunnels by name and custom domain
	byPort   map[int32]*tun.TunLiveTunnel
	relays   map[string]*tun.TunRelay
	fetched  time.Time     // when the copy was read
	tried    time.Time     // when the last fetch started
	fetching chan struct{} // closed when the running fetch ends; nil when none runs
}

// NewLiveView reads the live tables at most every ttl (and on a miss, at
// most once a second).
func NewLiveView(vnic ifs.IVNic, ttl time.Duration) *LiveView {
	return &LiveView{vnic: vnic, ttl: ttl}
}

// Tunnel returns the active tunnel serving host (<name>.<base> or a custom
// domain, else the closest wildcard domain covering it) and its relay. A miss, or an owner equal to stale (the caller's
// own relay ID, when it knows it doesn't serve the tunnel), refetches once.
func (v *LiveView) Tunnel(host, stale string) (*tun.TunLiveTunnel, *tun.TunRelay) {
	host = strings.ToLower(host)
	key := host
	if name := Cluster().Rules().TunnelName(host); name != "" {
		key = name
	}
	lookup := func() (*tun.TunLiveTunnel, *tun.TunRelay) {
		v.mu.Lock()
		defer v.mu.Unlock()
		t := v.byName[key]
		for _, w := range protocol.WildcardsOf(key) {
			if t != nil {
				break
			}
			t = v.byName[w]
		}
		return v.owner(t)
	}
	v.ensure(v.ttl, false)
	t, r := lookup()
	if t == nil || (stale != "" && t.RelayId == stale) {
		v.ensure(liveRefetchMin, true)
		t, r = lookup()
	}
	return t, r
}

// TunnelByPort returns the active tunnel holding a mode A port.
func (v *LiveView) TunnelByPort(port int32) (*tun.TunLiveTunnel, *tun.TunRelay) {
	lookup := func() (*tun.TunLiveTunnel, *tun.TunRelay) {
		v.mu.Lock()
		defer v.mu.Unlock()
		return v.owner(v.byPort[port])
	}
	v.ensure(v.ttl, false)
	t, r := lookup()
	if t == nil {
		v.ensure(liveRefetchMin, true)
		t, r = lookup()
	}
	return t, r
}

// Relays lists the relays that are up.
func (v *LiveView) Relays() []*tun.TunRelay {
	v.ensure(v.ttl, false)
	v.mu.Lock()
	defer v.mu.Unlock()
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
	v.fetched, v.tried = time.Time{}, time.Time{}
}

// owner is t with its relay, when both can serve (callers hold v.mu).
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

// ensure starts a background fetch when the copy is older than age, unless
// one runs or the last one started less than liveRefetchMin ago. A lookup
// that missed (miss), or that has no copy yet, waits for the fetch at most
// liveMissWait; any other returns at once.
func (v *LiveView) ensure(age time.Duration, miss bool) {
	v.mu.Lock()
	if time.Since(v.fetched) < age {
		v.mu.Unlock()
		return
	}
	if v.fetching == nil && time.Since(v.tried) >= liveRefetchMin {
		v.fetching, v.tried = make(chan struct{}), time.Now()
		go v.fetch(v.fetching)
	}
	done, empty := v.fetching, v.fetched.IsZero()
	v.mu.Unlock()
	if done == nil || (!miss && !empty) {
		return
	}
	select {
	case <-done:
	case <-time.After(liveMissWait):
	}
}

// fetch reads the tables and swaps them in; a failed read keeps the old
// copy.
func (v *LiveView) fetch(done chan struct{}) {
	defer close(done)
	tunnels, err1 := l8common.GetEntities(LiveService, AreaLive, &tun.TunLiveTunnel{}, v.vnic)
	var relays []interface{}
	var err2 error
	if err1 == nil {
		relays, err2 = l8common.GetEntities(RelayService, AreaLive, &tun.TunRelay{}, v.vnic)
	}
	v.mu.Lock()
	defer v.mu.Unlock()
	v.fetching = nil
	if err1 != nil || err2 != nil {
		return
	}
	byName, byPort, byRelay := map[string]*tun.TunLiveTunnel{}, map[int32]*tun.TunLiveTunnel{}, map[string]*tun.TunRelay{}
	for _, e := range tunnels {
		t, ok := e.(*tun.TunLiveTunnel)
		if !ok || t.Name == "" || t.Simulated || t.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			continue
		}
		byName[t.Name] = t
		for _, d := range t.Domains {
			byName[d] = t
		}
		if t.PublicPort != 0 {
			byPort[t.PublicPort] = t
		}
	}
	for _, e := range relays {
		if r, ok := e.(*tun.TunRelay); ok && r.RelayId != "" && !r.Simulated {
			byRelay[r.RelayId] = r
		}
	}
	v.byName, v.byPort, v.relays = byName, byPort, byRelay
	v.fetched = time.Now()
}
