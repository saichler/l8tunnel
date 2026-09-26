// Package claims is the cluster-wide claims engine that the registry
// process runs. It owns the live state of every relay, agent and tunnel,
// and serializes every claim, so two relays can never hand out the same
// tunnel name, public port or custom domain. It applies the same rules as
// a standalone relay (tunnel/registry). It has no framework dependencies:
// the registry feeds it requests and mirrors its changes into the Layer 8
// live tables through a Sink.
package claims

import (
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/registry"
	"github.com/saichler/l8tunnel/go/types/tun"
	"google.golang.org/protobuf/proto"
)

// Defaults for Config.
const (
	DefaultGrace            = 5 * time.Minute
	DefaultRelayTimeout     = 15 * time.Second
	DefaultOfflineRetention = 24 * time.Hour
	DefaultDownRetention    = time.Hour
)

// Change is what happened to a record.
type Change int

const (
	Created Change = iota + 1
	Updated
	Deleted
)

// Sink receives every change, as copies the engine no longer touches.
type Sink interface {
	TunnelChanged(rec *tun.TunLiveTunnel, change Change)
	AgentChanged(rec *tun.TunAgent, change Change)
	RelayChanged(rec *tun.TunRelay, change Change)
	// Command asks a relay (RelayId set) or every relay to act.
	Command(cmd *tun.TunCtlCommand)
}

// Directory is the management data a claim is checked against. The
// registry keeps a cached copy, so claims keep working while the
// management backend is down.
type Directory interface {
	Reservations() []*tun.TunReservation
	// IsSiteName reports whether host is an edge SITE domain's name, which
	// a tunnel can't take.
	IsSiteName(host string) bool
}

// Config configures an Engine.
type Config struct {
	Rules            registry.Rules
	Grace            time.Duration // names held after a disconnect
	RelayTimeout     time.Duration // a relay silent this long is lost
	OfflineRetention time.Duration // offline agents are kept this long
	DownRetention    time.Duration // lost relays are kept this long
	// AllowSimulated accepts records marked simulated (mock data).
	AllowSimulated bool
	// Now is the clock; nil means time.Now.
	Now func() time.Time
}

// Engine is the claims engine. Every method is safe for concurrent use.
type Engine struct {
	cfg  Config
	dir  Directory
	sink Sink

	mu       sync.Mutex
	tunnels  map[string]*tun.TunLiveTunnel // by name
	byPort   map[int32]string              // public port -> name
	byDomain map[string]string             // custom domain -> name
	agents   map[string]*tun.TunAgent      // by agent ID
	relays   map[string]*tun.TunRelay      // by relay ID
}

// New builds an engine; zero durations take the defaults.
func New(cfg Config, dir Directory, sink Sink) *Engine {
	if cfg.Grace == 0 {
		cfg.Grace = DefaultGrace
	}
	if cfg.RelayTimeout == 0 {
		cfg.RelayTimeout = DefaultRelayTimeout
	}
	if cfg.OfflineRetention == 0 {
		cfg.OfflineRetention = DefaultOfflineRetention
	}
	if cfg.DownRetention == 0 {
		cfg.DownRetention = DefaultDownRetention
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	return &Engine{
		cfg: cfg, dir: dir, sink: sink,
		tunnels: map[string]*tun.TunLiveTunnel{}, byPort: map[int32]string{}, byDomain: map[string]string{},
		agents: map[string]*tun.TunAgent{}, relays: map[string]*tun.TunRelay{},
	}
}

// Handle runs one relay request.
func (e *Engine) Handle(req *tun.TunClaimRequest) *tun.TunClaimResponse {
	if req.RelayId == "" {
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "relayId is required")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	switch req.Kind {
	case tun.TunClaimKind_TUN_CLAIM_KIND_CLAIM:
		return e.claim(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_PARK:
		e.park(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_RELEASE:
		e.release(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE:
		return e.announce(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_HEARTBEAT:
		e.heartbeat(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_UP:
		return e.agentUp(req)
	case tun.TunClaimKind_TUN_CLAIM_KIND_AGENT_DOWN:
		e.agentDown(req)
	default:
		return refuse(tun.TunClaimError_TUN_CLAIM_ERROR_INVALID, "the request kind is required")
	}
	return &tun.TunClaimResponse{}
}

// Snapshot copies the whole state, for reconciling the live tables.
func (e *Engine) Snapshot() ([]*tun.TunLiveTunnel, []*tun.TunAgent, []*tun.TunRelay) {
	e.mu.Lock()
	defer e.mu.Unlock()
	tunnels := make([]*tun.TunLiveTunnel, 0, len(e.tunnels))
	for _, t := range e.tunnels {
		tunnels = append(tunnels, cloneTunnel(t))
	}
	agents := make([]*tun.TunAgent, 0, len(e.agents))
	for _, a := range e.agents {
		agents = append(agents, cloneAgent(a))
	}
	relays := make([]*tun.TunRelay, 0, len(e.relays))
	for _, r := range e.relays {
		relays = append(relays, cloneRelay(r))
	}
	return tunnels, agents, relays
}

func (e *Engine) now() int64 {
	return e.cfg.Now().Unix()
}

func refuse(code tun.TunClaimError, msg string) *tun.TunClaimResponse {
	return &tun.TunClaimResponse{Error: code, Message: msg}
}

func cloneTunnel(t *tun.TunLiveTunnel) *tun.TunLiveTunnel { return proto.Clone(t).(*tun.TunLiveTunnel) }
func cloneAgent(a *tun.TunAgent) *tun.TunAgent            { return proto.Clone(a).(*tun.TunAgent) }
func cloneRelay(r *tun.TunRelay) *tun.TunRelay            { return proto.Clone(r).(*tun.TunRelay) }

// setTunnel stores rec (indexing its port and domains) and reports it.
func (e *Engine) setTunnel(rec *tun.TunLiveTunnel) {
	change := Created
	if old := e.tunnels[rec.Name]; old != nil {
		e.unindex(old)
		change = Updated
	}
	e.tunnels[rec.Name] = rec
	if rec.PublicPort != 0 {
		e.byPort[rec.PublicPort] = rec.Name
	}
	for _, d := range rec.Domains {
		e.byDomain[d] = rec.Name
	}
	e.sink.TunnelChanged(cloneTunnel(rec), change)
}

func (e *Engine) deleteTunnel(name string) {
	rec := e.tunnels[name]
	if rec == nil {
		return
	}
	e.unindex(rec)
	delete(e.tunnels, name)
	e.sink.TunnelChanged(cloneTunnel(rec), Deleted)
}

func (e *Engine) unindex(rec *tun.TunLiveTunnel) {
	if rec.PublicPort != 0 && e.byPort[rec.PublicPort] == rec.Name {
		delete(e.byPort, rec.PublicPort)
	}
	for _, d := range rec.Domains {
		if e.byDomain[d] == rec.Name {
			delete(e.byDomain, d)
		}
	}
}

func (e *Engine) setAgent(a *tun.TunAgent) {
	change := Created
	if e.agents[a.AgentId] != nil {
		change = Updated
	}
	e.agents[a.AgentId] = a
	e.sink.AgentChanged(cloneAgent(a), change)
}

func (e *Engine) setRelay(r *tun.TunRelay) {
	change := Created
	if e.relays[r.RelayId] != nil {
		change = Updated
	}
	e.relays[r.RelayId] = r
	e.sink.RelayChanged(cloneRelay(r), change)
}
