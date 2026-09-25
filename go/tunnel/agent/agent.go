package agent

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// Agent keeps a session to the relay and serves its tunnels, reconnecting
// whenever the session drops.
type Agent struct {
	cfg Config
	log *slog.Logger

	mu        sync.Mutex
	endpoints []*l8tunnel.Endpoint
	targets   map[string]int // tunnel ID -> index in cfg.Tunnels
	names     []string       // name per configured tunnel, once assigned
	ready     chan struct{}
	readyOnce sync.Once

	stats   []tunnelStats // per configured tunnel
	state   connState
	lastRTT atomic.Int64 // last heartbeat round trip, nanoseconds
}

// New validates cfg and returns an agent that isn't connected yet.
func New(cfg Config) (*Agent, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.AgentID == "" {
		cfg.AgentID = protocol.RandomID(8)
	}
	log := cfg.Logger.With("agent", cfg.AgentID)
	names := make([]string, len(cfg.Tunnels))
	for i, t := range cfg.Tunnels {
		names[i] = t.Name
		if t.InsecureSkipVerify {
			log.Warn("TLS certificate verification is disabled for this tunnel's target",
				"tunnel", t.Name, "target", t.targetString())
		}
	}
	return &Agent{
		cfg:     cfg,
		log:     log,
		targets: map[string]int{},
		names:   names,
		ready:   make(chan struct{}),
		stats:   make([]tunnelStats, len(cfg.Tunnels)),
	}, nil
}

// Ready is closed once the relay has registered every tunnel for the
// first time.
func (a *Agent) Ready() <-chan struct{} {
	return a.ready
}

// Endpoints returns the public endpoints from the latest registration.
func (a *Agent) Endpoints() []*l8tunnel.Endpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*l8tunnel.Endpoint, len(a.endpoints))
	copy(out, a.endpoints)
	return out
}

// Run keeps the agent connected until ctx is cancelled, reconnecting with
// exponential backoff and jitter when the session drops. The backoff
// resets after every session that registered its tunnels. An Error from
// the relay (bad token, name taken, invalid request...) is not retried:
// Run returns it. On cancellation Run returns ctx.Err().
func (a *Agent) Run(ctx context.Context) error {
	delay := a.cfg.ReconnectMin
	for {
		registered, err := a.runSession(ctx)
		a.setDisconnected(err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		if isFatal(err) {
			return err
		}
		if registered {
			delay = a.cfg.ReconnectMin
		}
		wait := jitter(delay)
		a.log.Warn("relay session ended, reconnecting", "error", err, "in", wait.String())
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(wait):
		}
		delay = min(delay*2, a.cfg.ReconnectMax)
	}
}

// fatalError marks a session error that reconnecting can't fix.
type fatalError struct {
	error
}

func (e fatalError) Unwrap() error { return e.error }

func isFatal(err error) bool {
	var rerr *protocol.RemoteError
	var ferr fatalError
	return errors.As(err, &rerr) || errors.As(err, &ferr)
}

// jitter spreads d by +/-20% so many agents don't reconnect in lockstep.
func jitter(d time.Duration) time.Duration {
	return d + time.Duration((rand.Float64()*0.4-0.2)*float64(d))
}

// setEndpoints maps the relay's endpoints, returned in request order, to
// the configured targets, and remembers assigned names so reconnects ask
// for the same ones.
func (a *Agent) setEndpoints(endpoints []*l8tunnel.Endpoint) error {
	if len(endpoints) != len(a.cfg.Tunnels) {
		return fatalError{errors.New("relay returned a different number of endpoints than tunnels requested")}
	}
	a.mu.Lock()
	a.endpoints = endpoints
	a.targets = map[string]int{}
	for i, ep := range endpoints {
		a.targets[ep.GetTunnelId()] = i
		a.names[i] = ep.GetName()
		a.logEndpoint(ep, a.cfg.Tunnels[i].targetString())
	}
	a.state.connected = true
	a.state.since = time.Now()
	a.mu.Unlock()
	a.readyOnce.Do(func() { close(a.ready) })
	return nil
}

func (a *Agent) logEndpoint(ep *l8tunnel.Endpoint, target string) {
	args := []interface{}{"name", ep.GetName(), "type", ep.GetType().String(), "target", target,
		"public", ep.GetPublicAddress(), "hostname", ep.GetHostname()}
	if ep.GetType() == l8tunnel.TunnelType_TUNNEL_TYPE_SSH {
		args = append(args, "ssh_mode_a", fmt.Sprintf("ssh -p %d <user>@%s", ep.GetPublicPort(), hostOf(ep.GetPublicAddress())),
			"ssh_mode_b", "ssh -o ProxyCommand='l8tunnel connect %h' <user>@"+ep.GetHostname())
	}
	a.log.Info("tunnel ready", args...)
}

func (a *Agent) requestedName(i int) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.names[i]
}

func (a *Agent) tunnelFor(tunnelID string) (TunnelConfig, *tunnelStats, bool) {
	a.mu.Lock()
	defer a.mu.Unlock()
	i, ok := a.targets[tunnelID]
	if !ok {
		return TunnelConfig{}, nil, false
	}
	return a.cfg.Tunnels[i], &a.stats[i], true
}
