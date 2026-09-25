package relay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// handshakeTimeout bounds each step of session setup (TLS handshake,
// control stream, Hello), so idle connections can't pin resources.
const handshakeTimeout = 10 * time.Second

// agentSession is one authenticated agent connection.
type agentSession struct {
	server   *Server
	id       string
	token    string // name of the token the agent authenticated with
	agentID  string
	log      *slog.Logger
	mux      *transport.Session
	control  *transport.Stream
	writeMu  sync.Mutex
	lastSeen atomic.Int64 // unix nanos of the last control message
	// tunnels is only touched by the session's control-loop goroutine.
	tunnels []*tunnel
}

// serveAgent runs an agent session on a connection that negotiated the
// l8tunnel ALPN on the control SNI.
func (s *Server) serveAgent(conn *tls.Conn, log *slog.Logger) {
	mux, err := transport.NewServerSession(conn, log)
	if err != nil {
		log.Warn("agent session setup failed", "error", err)
		return
	}
	defer mux.Close()

	sess := &agentSession{server: s, id: protocol.RandomID(8), log: log, mux: mux}
	if !s.track(sess) {
		return
	}
	defer s.untrack(sess)
	defer sess.closeTunnels()

	if err := sess.handshake(); err != nil {
		log.Warn("agent rejected", "error", err)
		return
	}
	sess.lastSeen.Store(time.Now().UnixNano())
	s.goTracked(sess.watchdog)
	sess.controlLoop()
	sess.log.Info("agent disconnected")
}

// handshake accepts the control stream, authenticates Hello and replies
// with Welcome or an Error.
func (sess *agentSession) handshake() error {
	timer := time.AfterFunc(handshakeTimeout, func() { sess.mux.Close() })
	control, err := sess.mux.Accept()
	timer.Stop()
	if err != nil {
		return fmt.Errorf("no control stream: %w", err)
	}
	sess.control = control

	if err := control.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return err
	}
	msg := &l8tunnel.ControlMessage{}
	if err := protocol.ReadMessage(control, msg); err != nil {
		return fmt.Errorf("read hello: %w", err)
	}
	if err := control.SetReadDeadline(time.Time{}); err != nil {
		return err
	}
	hello := msg.GetHello()
	if hello == nil {
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "expected Hello"))
		return fmt.Errorf("first control message was not Hello")
	}
	if hello.GetProtocolVersion() != protocol.Version {
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_UNSUPPORTED_VERSION,
			"relay speaks protocol version %d, agent sent %d", protocol.Version, hello.GetProtocolVersion()))
		return fmt.Errorf("unsupported protocol version %d", hello.GetProtocolVersion())
	}
	tokenName, ok := sess.server.cfg.Tokens.Verify(hello.GetToken())
	if !ok {
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED, "invalid token"))
		return fmt.Errorf("invalid token from agent %q", hello.GetAgentId())
	}
	if hello.GetAgentId() == "" {
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "agent ID is required"))
		return fmt.Errorf("hello without agent ID")
	}

	sess.token = tokenName
	sess.agentID = hello.GetAgentId()
	sess.log = sess.log.With("session", sess.id, "token", tokenName, "agent", sess.agentID)
	sess.log.Info("agent connected", "version", hello.GetAgentVersion(),
		"os", hello.GetOs(), "arch", hello.GetArch())
	return sess.send(&l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Welcome{
		Welcome: &l8tunnel.Welcome{
			SessionId:           sess.id,
			HeartbeatIntervalMs: sess.server.cfg.HeartbeatInterval.Milliseconds(),
		},
	}})
}

func (sess *agentSession) controlLoop() {
	for {
		msg := &l8tunnel.ControlMessage{}
		if err := protocol.ReadMessage(sess.control, msg); err != nil {
			if !errors.Is(err, io.EOF) {
				sess.log.Warn("control stream ended", "error", err)
			}
			return
		}
		sess.lastSeen.Store(time.Now().UnixNano())
		var reply *l8tunnel.ControlMessage
		switch body := msg.GetBody().(type) {
		case *l8tunnel.ControlMessage_Register:
			reply = sess.register(body.Register)
		case *l8tunnel.ControlMessage_Ping:
			reply = &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Pong{
				Pong: &l8tunnel.Pong{Nonce: body.Ping.GetNonce(), SentUnixNano: body.Ping.GetSentUnixNano()},
			}}
		default:
			reply = protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"unexpected control message %T", body)
		}
		if err := sess.send(reply); err != nil {
			sess.log.Warn("control reply failed", "error", err)
			return
		}
	}
}

// watchdog drops the session when the agent misses too many heartbeats.
func (sess *agentSession) watchdog() {
	interval := sess.server.cfg.HeartbeatInterval
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-sess.mux.Done():
			return
		case <-ticker.C:
			silent := time.Since(time.Unix(0, sess.lastSeen.Load()))
			if silent > missedHeartbeats*interval {
				sess.log.Warn("agent missed heartbeats, dropping session", "silent", silent.String())
				sess.mux.Close()
				return
			}
		}
	}
}

// register opens every requested tunnel, or none of them.
func (sess *agentSession) register(req *l8tunnel.Register) *l8tunnel.ControlMessage {
	if len(req.GetTunnels()) == 0 {
		return protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "no tunnels requested")
	}
	var opened []*tunnel
	for _, spec := range req.GetTunnels() {
		t, err := sess.server.openTunnel(sess, spec)
		if err != nil {
			for _, o := range opened {
				o.close()
				sess.server.registry.rollback(o.res, sess, o.existed)
			}
			sess.log.Warn("tunnel registration rejected", "name", spec.GetName(), "error", err)
			var rerr *protocol.RemoteError
			if errors.As(err, &rerr) {
				return protocol.ErrorMessage(rerr.Code, "%s", rerr.Message)
			}
			return protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "%v", err)
		}
		opened = append(opened, t)
	}
	endpoints := make([]*l8tunnel.Endpoint, 0, len(opened))
	for _, t := range opened {
		sess.tunnels = append(sess.tunnels, t)
		endpoints = append(endpoints, t.endpoint)
		if t.listener != nil {
			sess.server.goTracked(t.serve)
		}
		sess.log.Info("tunnel open", "name", t.endpoint.GetName(), "type", t.endpoint.GetType().String(),
			"public", t.endpoint.GetPublicAddress(), "hostname", t.endpoint.GetHostname(), "reclaimed", t.existed)
	}
	return &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Registered{
		Registered: &l8tunnel.Registered{Endpoints: endpoints},
	}}
}

// closeTunnels stops the session's listeners and parks their reservations
// for the grace period.
func (sess *agentSession) closeTunnels() {
	for _, t := range sess.tunnels {
		t.close()
		sess.server.registry.park(t.res, sess)
	}
	sess.tunnels = nil
}

func (sess *agentSession) send(msg *l8tunnel.ControlMessage) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	return protocol.WriteMessage(sess.control, msg)
}
