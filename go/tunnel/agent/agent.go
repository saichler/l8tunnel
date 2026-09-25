package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"runtime"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

const handshakeTimeout = 10 * time.Second

// Agent keeps a session to the relay and serves its tunnels.
type Agent struct {
	cfg Config
	log *slog.Logger

	mu        sync.Mutex
	endpoints []*l8tunnel.Endpoint
	targets   map[string]string // tunnel ID -> local target
	ready     chan struct{}
	readyOnce sync.Once
}

// New validates cfg and returns an agent that isn't connected yet.
func New(cfg Config) (*Agent, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	if cfg.AgentID == "" {
		cfg.AgentID = protocol.RandomID(8)
	}
	return &Agent{
		cfg:     cfg,
		log:     cfg.Logger.With("agent", cfg.AgentID),
		targets: map[string]string{},
		ready:   make(chan struct{}),
	}, nil
}

// Ready is closed once the relay has registered every tunnel.
func (a *Agent) Ready() <-chan struct{} {
	return a.ready
}

// Endpoints returns the public endpoints the relay assigned.
func (a *Agent) Endpoints() []*l8tunnel.Endpoint {
	a.mu.Lock()
	defer a.mu.Unlock()
	out := make([]*l8tunnel.Endpoint, len(a.endpoints))
	copy(out, a.endpoints)
	return out
}

// Run connects to the relay, registers the tunnels and serves them until
// ctx is cancelled or the session ends. It returns ctx.Err() on
// cancellation, and the reason the session ended otherwise.
func (a *Agent) Run(ctx context.Context) error {
	conn, err := transport.DialRelay(ctx, a.cfg.RelayAddr, a.cfg.TLS)
	if err != nil {
		return err
	}
	mux, err := transport.NewClientSession(conn, a.log)
	if err != nil {
		conn.Close()
		return err
	}
	defer mux.Close()
	stop := context.AfterFunc(ctx, func() { mux.Close() })
	defer stop()

	control, err := mux.Open()
	if err != nil {
		return a.sessionErr(ctx, err)
	}
	if err := a.handshake(control); err != nil {
		return a.sessionErr(ctx, err)
	}

	controlErr := make(chan error, 1)
	go func() {
		controlErr <- a.readControl(control)
		mux.Close()
	}()

	var streams sync.WaitGroup
	for {
		stream, err := mux.Accept()
		if err != nil {
			break
		}
		streams.Add(1)
		go func() {
			defer streams.Done()
			a.serveStream(ctx, stream)
		}()
	}
	mux.Close()
	streams.Wait()
	return a.sessionErr(ctx, <-controlErr)
}

func (a *Agent) sessionErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if err == nil || errors.Is(err, io.EOF) {
		return fmt.Errorf("relay closed the session")
	}
	return err
}

// handshake sends Hello and Register and waits for Welcome and Registered.
func (a *Agent) handshake(control *transport.Stream) error {
	if err := control.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	hello := &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Hello{Hello: &l8tunnel.Hello{
		ProtocolVersion: protocol.Version,
		Token:           a.cfg.Token,
		AgentId:         a.cfg.AgentID,
		AgentVersion:    a.cfg.Version,
		Os:              runtime.GOOS,
		Arch:            runtime.GOARCH,
	}}}
	reply, err := a.exchange(control, hello)
	if err != nil {
		return fmt.Errorf("hello: %w", err)
	}
	if reply.GetWelcome() == nil {
		return fmt.Errorf("hello: expected Welcome, got %T", reply.GetBody())
	}

	specs := make([]*l8tunnel.TunnelSpec, 0, len(a.cfg.Tunnels))
	for _, t := range a.cfg.Tunnels {
		specs = append(specs, &l8tunnel.TunnelSpec{Name: t.Name, Type: t.Type, PublicPort: t.PublicPort})
	}
	reply, err = a.exchange(control, &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Register{
		Register: &l8tunnel.Register{Tunnels: specs},
	}})
	if err != nil {
		return fmt.Errorf("register: %w", err)
	}
	registered := reply.GetRegistered()
	if registered == nil {
		return fmt.Errorf("register: expected Registered, got %T", reply.GetBody())
	}
	if err := a.setEndpoints(registered.GetEndpoints()); err != nil {
		return err
	}
	return control.SetDeadline(time.Time{})
}

// exchange sends msg and reads one reply, turning an Error into a Go error.
func (a *Agent) exchange(control *transport.Stream, msg *l8tunnel.ControlMessage) (*l8tunnel.ControlMessage, error) {
	if err := protocol.WriteMessage(control, msg); err != nil {
		return nil, err
	}
	reply := &l8tunnel.ControlMessage{}
	if err := protocol.ReadMessage(control, reply); err != nil {
		return nil, err
	}
	if e := reply.GetError(); e != nil {
		return nil, protocol.NewRemoteError(e)
	}
	return reply, nil
}

// setEndpoints maps the relay's endpoints, returned in request order, to
// the configured targets.
func (a *Agent) setEndpoints(endpoints []*l8tunnel.Endpoint) error {
	if len(endpoints) != len(a.cfg.Tunnels) {
		return fmt.Errorf("relay returned %d endpoints for %d tunnels", len(endpoints), len(a.cfg.Tunnels))
	}
	a.mu.Lock()
	a.endpoints = endpoints
	a.targets = map[string]string{}
	for i, ep := range endpoints {
		a.targets[ep.GetTunnelId()] = a.cfg.Tunnels[i].Target
		a.log.Info("tunnel ready", "name", ep.GetName(), "type", ep.GetType().String(),
			"public", ep.GetPublicAddress(), "target", a.cfg.Tunnels[i].Target)
	}
	a.mu.Unlock()
	a.readyOnce.Do(func() { close(a.ready) })
	return nil
}

func (a *Agent) targetFor(tunnelID string) string {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.targets[tunnelID]
}

// readControl reads control messages until the stream ends. An Error from
// the relay ends the session.
func (a *Agent) readControl(control *transport.Stream) error {
	for {
		msg := &l8tunnel.ControlMessage{}
		if err := protocol.ReadMessage(control, msg); err != nil {
			return err
		}
		switch body := msg.GetBody().(type) {
		case *l8tunnel.ControlMessage_Error:
			return protocol.NewRemoteError(body.Error)
		case *l8tunnel.ControlMessage_Pong:
		default:
			a.log.Warn("unexpected control message from relay", "type", fmt.Sprintf("%T", body))
		}
	}
}
