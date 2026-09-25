package relay

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
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
	server  *Server
	id      string
	log     *slog.Logger
	mux     *transport.Session
	control *transport.Stream
	writeMu sync.Mutex
	// tunnels is only touched by the session's control-loop goroutine.
	tunnels []*tcpTunnel
}

func (s *Server) serveAgent(conn *tls.Conn) {
	defer conn.Close()
	remote := conn.RemoteAddr().String()
	log := s.log.With("remote", remote)

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		log.Warn("agent TLS handshake failed", "error", err)
		return
	}
	if err := transport.CheckALPN(conn); err != nil {
		log.Warn("rejected non-agent connection", "error", err)
		return
	}

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
	sess.controlLoop()
	log.Info("agent disconnected", "session", sess.id)
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

	sess.log = sess.log.With("session", sess.id, "token", tokenName, "agent", hello.GetAgentId())
	sess.log.Info("agent connected", "version", hello.GetAgentVersion(),
		"os", hello.GetOs(), "arch", hello.GetArch())
	return sess.send(&l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Welcome{
		Welcome: &l8tunnel.Welcome{SessionId: sess.id},
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

// register opens every requested tunnel, or none of them.
func (sess *agentSession) register(req *l8tunnel.Register) *l8tunnel.ControlMessage {
	if len(req.GetTunnels()) == 0 {
		return protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "no tunnels requested")
	}
	var opened []*tcpTunnel
	for _, spec := range req.GetTunnels() {
		t, err := sess.server.openTunnel(sess, spec)
		if err != nil {
			for _, o := range opened {
				o.close()
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
		sess.server.goTracked(t.serve)
		sess.log.Info("tunnel open", "name", t.endpoint.GetName(),
			"type", t.endpoint.GetType().String(), "public", t.endpoint.GetPublicAddress())
	}
	return &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Registered{
		Registered: &l8tunnel.Registered{Endpoints: endpoints},
	}}
}

func (sess *agentSession) closeTunnels() {
	for _, t := range sess.tunnels {
		t.close()
	}
	sess.tunnels = nil
}

func (sess *agentSession) send(msg *l8tunnel.ControlMessage) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	return protocol.WriteMessage(sess.control, msg)
}
