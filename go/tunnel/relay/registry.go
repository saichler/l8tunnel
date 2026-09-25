package relay

import (
	"regexp"
	"sync"
)

// namePattern keeps tunnel names valid as DNS labels, since HTTP tunnels
// become <name>.<base-domain>.
var namePattern = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// registry tracks the tunnel names and public ports in use on the relay.
type registry struct {
	mu    sync.Mutex
	names map[string]struct{}
	ports map[int]struct{}
}

func newRegistry() *registry {
	return &registry{names: map[string]struct{}{}, ports: map[int]struct{}{}}
}

func (r *registry) reserveName(name string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, taken := r.names[name]; taken {
		return false
	}
	r.names[name] = struct{}{}
	return true
}

func (r *registry) releaseName(name string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.names, name)
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
