package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

const (
	handshakeTimeout = 10 * time.Second
	// missedHeartbeats is how many intervals may pass without a Pong before
	// the agent drops the session and reconnects.
	missedHeartbeats = 3
)

// sessionEnd records the first reason a session ended.
type sessionEnd struct {
	once sync.Once
	err  error
}

func (e *sessionEnd) set(err error) {
	e.once.Do(func() { e.err = err })
}

// runSession connects, registers the tunnels and serves them until the
// session ends. registered reports whether registration succeeded.
func (a *Agent) runSession(ctx context.Context) (registered bool, err error) {
	conn, err := transport.DialRelay(ctx, a.cfg.RelayAddr, a.cfg.TLS)
	if err != nil {
		return false, err
	}
	mux, err := transport.NewClientSession(conn, a.log)
	if err != nil {
		conn.Close()
		return false, err
	}
	defer mux.Close()
	stop := context.AfterFunc(ctx, func() { mux.Close() })
	defer stop()

	control, err := mux.Open()
	if err != nil {
		return false, err
	}
	interval, err := a.handshake(control)
	if err != nil {
		return false, err
	}

	end := &sessionEnd{}
	var lastPong atomic.Int64
	lastPong.Store(time.Now().UnixNano())
	go func() {
		end.set(a.readControl(control, &lastPong))
		mux.Close()
	}()
	go func() {
		end.set(a.heartbeat(control, mux, interval, &lastPong))
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
	end.set(errors.New("session closed"))
	if end.err == nil || errors.Is(end.err, io.EOF) {
		return true, errors.New("relay closed the session")
	}
	return true, end.err
}

// handshake sends Hello and Register, waits for Welcome and Registered,
// and returns the heartbeat interval the relay asked for.
func (a *Agent) handshake(control *transport.Stream) (time.Duration, error) {
	if err := control.SetDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return 0, err
	}
	hello := &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Hello{Hello: &l8tunnel.Hello{
		ProtocolVersion: protocol.Version,
		Token:           a.cfg.Token,
		AgentId:         a.cfg.AgentID,
		AgentVersion:    a.cfg.Version,
		Os:              runtime.GOOS,
		Arch:            runtime.GOARCH,
	}}}
	reply, err := exchange(control, hello)
	if err != nil {
		return 0, fmt.Errorf("hello: %w", err)
	}
	welcome := reply.GetWelcome()
	if welcome == nil {
		return 0, fatalError{fmt.Errorf("hello: expected Welcome, got %T", reply.GetBody())}
	}
	interval := time.Duration(welcome.GetHeartbeatIntervalMs()) * time.Millisecond
	if interval <= 0 {
		return 0, fatalError{fmt.Errorf("relay sent heartbeat interval %s", interval)}
	}

	specs := make([]*l8tunnel.TunnelSpec, 0, len(a.cfg.Tunnels))
	for i, t := range a.cfg.Tunnels {
		specs = append(specs, &l8tunnel.TunnelSpec{Name: a.requestedName(i), Type: t.Type, PublicPort: t.PublicPort})
	}
	reply, err = exchange(control, &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Register{
		Register: &l8tunnel.Register{Tunnels: specs},
	}})
	if err != nil {
		return 0, fmt.Errorf("register: %w", err)
	}
	registered := reply.GetRegistered()
	if registered == nil {
		return 0, fatalError{fmt.Errorf("register: expected Registered, got %T", reply.GetBody())}
	}
	if err := a.setEndpoints(registered.GetEndpoints()); err != nil {
		return 0, err
	}
	return interval, control.SetDeadline(time.Time{})
}

// exchange sends msg and reads one reply, turning an Error into a Go error.
func exchange(control *transport.Stream, msg *l8tunnel.ControlMessage) (*l8tunnel.ControlMessage, error) {
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

// readControl reads control messages until the stream ends. An Error from
// the relay ends the session.
func (a *Agent) readControl(control *transport.Stream, lastPong *atomic.Int64) error {
	for {
		msg := &l8tunnel.ControlMessage{}
		if err := protocol.ReadMessage(control, msg); err != nil {
			return err
		}
		switch body := msg.GetBody().(type) {
		case *l8tunnel.ControlMessage_Error:
			return protocol.NewRemoteError(body.Error)
		case *l8tunnel.ControlMessage_Pong:
			now := time.Now().UnixNano()
			lastPong.Store(now)
			a.log.Debug("heartbeat", "rtt", time.Duration(now-body.Pong.GetSentUnixNano()).String())
		default:
			a.log.Warn("unexpected control message from relay", "type", fmt.Sprintf("%T", body))
		}
	}
}

// heartbeat sends a Ping every interval, and ends the session when the
// relay hasn't answered for missedHeartbeats intervals. It is the only
// writer on the control stream after the handshake.
func (a *Agent) heartbeat(control *transport.Stream, mux *transport.Session, interval time.Duration, lastPong *atomic.Int64) error {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	var nonce uint64
	for {
		select {
		case <-mux.Done():
			return nil
		case <-ticker.C:
			if silent := time.Since(time.Unix(0, lastPong.Load())); silent > missedHeartbeats*interval {
				return fmt.Errorf("relay missed heartbeats for %s", silent)
			}
			nonce++
			ping := &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Ping{
				Ping: &l8tunnel.Ping{Nonce: nonce, SentUnixNano: time.Now().UnixNano()},
			}}
			if err := protocol.WriteMessage(control, ping); err != nil {
				return fmt.Errorf("send heartbeat: %w", err)
			}
		}
	}
}

func hostOf(addr string) string {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return addr
	}
	return host
}
