package relay

import (
	"errors"
	"regexp"
	"sort"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// namePattern keeps tunnel names valid as DNS labels, since tunnels are
// reachable as <name>.<base-domain>.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservation holds a tunnel name, and its public port, for one token.
// While the owning session is connected it is active. When the session
// ends it is parked: for the grace period, or indefinitely if permanent.
type reservation struct {
	name      string
	typ       l8tunnel.TunnelType
	tokenID   string
	agentID   string
	port      int           // TCP/SSH only
	permanent bool          // operator reservation; never expires
	session   *agentSession // nil while parked
	tunnel    *tunnel       // nil while parked
	timer     *time.Timer   // grace-period expiry while parked
	expires   time.Time     // when a parked, non-permanent reservation expires
}

// registry tracks the tunnel names and public ports in use on the relay.
type registry struct {
	mu     sync.Mutex
	grace  time.Duration
	names  map[string]*reservation
	ports  map[int]struct{}
	closed bool
}

func newRegistry(grace time.Duration) *registry {
	return &registry{grace: grace, names: map[string]*reservation{}, ports: map[int]struct{}{}}
}

var (
	errNameTaken  = errors.New("name taken")
	errMaxTunnels = errors.New("token's tunnel limit reached")
	errPortTaken  = errors.New("port taken")
)

// claim reserves name for sess. A parked reservation of the same token is
// reclaimed. An active one of the same token and agent ID is taken over:
// the agent reconnected before the relay noticed its old session died.
// maxTunnels (0 = no cap) limits the token's active tunnels. existed
// reports whether the reservation was reclaimed or taken over.
func (r *registry) claim(name string, typ l8tunnel.TunnelType, tokenID, agentID string, sess *agentSession, maxTunnels int) (res *reservation, existed bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res = r.names[name]
	if res != nil && res.tokenID != tokenID {
		return nil, false, errNameTaken
	}
	if res != nil && res.session != nil && (res.agentID != agentID || res.session == sess) {
		return nil, false, errNameTaken
	}
	if maxTunnels > 0 && r.activeLocked(tokenID, res) >= maxTunnels {
		return nil, false, errMaxTunnels
	}
	if res == nil {
		res = &reservation{name: name, typ: typ, tokenID: tokenID, agentID: agentID, session: sess}
		r.names[name] = res
		return res, false, nil
	}
	if res.session != nil {
		// Take over: stop the stale session's listener so the port can be
		// bound again. The stale session's cleanup won't park it, because
		// the reservation no longer points at that session.
		if res.tunnel != nil {
			res.tunnel.close()
		}
		res.session.log.Info("tunnel taken over by reconnected agent", "name", name)
	}
	if res.timer != nil {
		res.timer.Stop()
		res.timer = nil
	}
	res.typ = typ
	res.agentID = agentID
	res.session = sess
	res.tunnel = nil
	return res, true, nil
}

// activeLocked counts tokenID's active tunnels, not counting except.
func (r *registry) activeLocked(tokenID string, except *reservation) int {
	n := 0
	for _, res := range r.names {
		if res.tokenID == tokenID && res.session != nil && res != except {
			n++
		}
	}
	return n
}

// activate records the tunnel now serving res.
func (r *registry) activate(res *reservation, t *tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.tunnel = t
}

// park keeps res reserved after sess ends: for the grace period, or until
// an operator removes it if permanent. It does nothing if another session
// took res over.
func (r *registry) park(res *reservation, sess *agentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res.session != sess {
		return
	}
	res.session = nil
	res.tunnel = nil
	if r.names[res.name] != res {
		return // released (token revoked) while active
	}
	if r.closed && !res.permanent {
		r.deleteLocked(res)
		return
	}
	if !res.permanent {
		res.expires = time.Now().Add(r.grace)
		res.timer = time.AfterFunc(r.grace, func() { r.expire(res) })
	}
}

// rollback undoes a claim whose tunnel failed to open: a reclaimed
// reservation is parked again, a new one is released.
func (r *registry) rollback(res *reservation, sess *agentSession, existed bool) {
	if existed {
		r.park(res, sess)
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if res.session == sess {
		r.deleteLocked(res)
	}
}

func (r *registry) expire(res *reservation) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.names[res.name] == res && res.session == nil && !res.permanent {
		r.deleteLocked(res)
	}
}

func (r *registry) deleteLocked(res *reservation) {
	if res.timer != nil {
		res.timer.Stop()
		res.timer = nil
	}
	if r.names[res.name] == res {
		delete(r.names, res.name)
	}
	if res.port != 0 {
		delete(r.ports, res.port)
	}
}

// reserve makes name a permanent reservation of tokenID. An existing
// reservation must belong to the same token; it becomes permanent (and
// keeps its port unless port is set).
func (r *registry) reserve(name, tokenID string, port int) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.names[name]
	if res != nil && res.tokenID != tokenID {
		return errNameTaken
	}
	if port != 0 && (res == nil || res.port != port) {
		if _, taken := r.ports[port]; taken {
			return errPortTaken
		}
	}
	if res == nil {
		res = &reservation{name: name, tokenID: tokenID}
		r.names[name] = res
	}
	if port != 0 && res.port != port {
		if res.port != 0 {
			delete(r.ports, res.port)
		}
		res.port = port
		r.ports[port] = struct{}{}
	}
	res.permanent = true
	if res.timer != nil {
		res.timer.Stop()
		res.timer = nil
	}
	return nil
}

// unreserve makes name's reservation non-permanent: released now if
// parked, or parked for the grace period when its session ends.
func (r *registry) unreserve(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.names[name]
	if res == nil || !res.permanent {
		return
	}
	res.permanent = false
	if res.session == nil {
		r.deleteLocked(res)
	}
}

// releaseToken drops every reservation of a revoked token and returns the
// sessions still using it.
func (r *registry) releaseToken(tokenID string) []*agentSession {
	r.mu.Lock()
	defer r.mu.Unlock()
	var sessions []*agentSession
	for _, res := range r.names {
		if res.tokenID == tokenID {
			if res.session != nil {
				sessions = append(sessions, res.session)
			}
			r.deleteLocked(res)
		}
	}
	return sessions
}

// lookup returns the tunnel serving name (nil while parked) and the
// reservation's type; found is false when the name isn't reserved.
func (r *registry) lookup(name string) (t *tunnel, typ l8tunnel.TunnelType, found bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res := r.names[name]
	if res == nil {
		return nil, l8tunnel.TunnelType_TUNNEL_TYPE_UNSPECIFIED, false
	}
	return res.tunnel, res.typ, true
}

func (r *registry) reservePort(port int) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.ports[port]; taken {
		return false
	}
	r.ports[port] = struct{}{}
	return true
}

func (r *registry) releasePort(port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.ports, port)
}

// setPort records res's public port, releasing the one it held before.
func (r *registry) setPort(res *reservation, port int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res.port != 0 && res.port != port {
		delete(r.ports, res.port)
	}
	res.port = port
}

// portOf returns the public port res holds, or 0.
func (r *registry) portOf(res *reservation) int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return res.port
}

// ParkedTunnel describes a reservation without a connected agent.
type ParkedTunnel struct {
	Name      string    `json:"name"`
	TokenID   string    `json:"token_id"`
	Type      string    `json:"type,omitempty"`
	Port      int       `json:"port,omitempty"`
	Permanent bool      `json:"permanent"`
	Expires   time.Time `json:"expires,omitempty"`
}

// parked lists reservations without a connected agent, sorted by name.
func (r *registry) parked() []ParkedTunnel {
	r.mu.Lock()
	defer r.mu.Unlock()
	var out []ParkedTunnel
	for _, res := range r.names {
		if res.session != nil {
			continue
		}
		p := ParkedTunnel{Name: res.name, TokenID: res.tokenID, Port: res.port, Permanent: res.permanent}
		if res.typ != l8tunnel.TunnelType_TUNNEL_TYPE_UNSPECIFIED {
			p.Type = protocol.TunnelTypeName(res.typ)
		}
		if !res.permanent {
			p.Expires = res.expires
		}
		out = append(out, p)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// close stops every grace timer and releases non-permanent parked
// reservations.
func (r *registry) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, res := range r.names {
		if res.session == nil {
			if res.timer != nil {
				res.timer.Stop()
				res.timer = nil
			}
			if !res.permanent {
				r.deleteLocked(res)
			}
		}
	}
}
