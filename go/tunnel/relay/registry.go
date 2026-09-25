package relay

import (
	"regexp"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// namePattern keeps tunnel names valid as DNS labels, since tunnels are
// reachable as <name>.<base-domain>.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// reservation holds a tunnel name, and its public port, for one token.
// While the owning session is connected it is active; after the session
// ends it is parked for the grace period so the same token can reclaim the
// same name and port.
type reservation struct {
	name    string
	typ     l8tunnel.TunnelType
	token   string
	agentID string
	port    int           // TCP/SSH only
	session *agentSession // nil while parked
	tunnel  *tunnel       // nil while parked
	timer   *time.Timer   // grace-period expiry while parked
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

// errNameTaken is returned by claim when another token (or another agent
// of the same token) holds the name.
type errNameTaken struct{}

func (errNameTaken) Error() string { return "name taken" }

// claim reserves name for sess. A parked reservation of the same token is
// reclaimed. An active one of the same token and agent ID is taken over:
// the agent reconnected before the relay noticed its old session died.
// existed reports whether the reservation was reclaimed or taken over.
func (r *registry) claim(name string, typ l8tunnel.TunnelType, token, agentID string, sess *agentSession) (res *reservation, existed bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res = r.names[name]
	if res == nil {
		res = &reservation{name: name, typ: typ, token: token, agentID: agentID, session: sess}
		r.names[name] = res
		return res, false, nil
	}
	if res.token != token {
		return nil, false, errNameTaken{}
	}
	if res.session != nil {
		if res.agentID != agentID || res.session == sess {
			return nil, false, errNameTaken{}
		}
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

// activate records the tunnel now serving res.
func (r *registry) activate(res *reservation, t *tunnel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	res.tunnel = t
}

// park keeps res reserved for the grace period after sess ends. It does
// nothing if another session took res over.
func (r *registry) park(res *reservation, sess *agentSession) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if res.session != sess {
		return
	}
	res.session = nil
	res.tunnel = nil
	if r.closed {
		r.deleteLocked(res)
		return
	}
	res.timer = time.AfterFunc(r.grace, func() { r.expire(res) })
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
	if r.names[res.name] == res && res.session == nil {
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

// close stops every grace timer and releases parked reservations.
func (r *registry) close() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.closed = true
	for _, res := range r.names {
		if res.session == nil {
			r.deleteLocked(res)
		}
	}
}
