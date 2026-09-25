package relay

import (
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// handshakeTimeout bounds each step of session setup (TLS handshake,
// control stream, Hello), so idle connections can't pin resources.
const handshakeTimeout = 10 * time.Second

// agentSession is one authenticated agent connection.
type agentSession struct {
	server      *Server
	id          string
	remote      string
	token       *auth.TokenRecord // set by the handshake
	peer        *x509.Certificate // verified client certificate, if any
	agentID     string
	hello       *l8tunnel.Hello
	connectedAt time.Time
	log         *slog.Logger
	mux         *transport.Session
	control     *transport.Stream
	writeMu     sync.Mutex
	lastSeen    atomic.Int64 // unix nanos of the last control message
	rttMicros   atomic.Int64 // the agent's last reported heartbeat round trip
	reason      atomic.Int32 // DisconnectReason; the first closer sets it
	websocket   bool
	// tunnelsMu guards the handshake fields read by Status and tunnels.
	tunnelsMu sync.Mutex
	tunnels   []*tunnel
}

// serveAgent runs an agent session on a connection that negotiated the
// l8tunnel ALPN on the control SNI.
func (s *Server) serveAgent(conn net.Conn, log *slog.Logger, peer *x509.Certificate, websocket bool) {
	ip := remoteIP(conn.RemoteAddr())
	if s.authFailures.Exhausted(ip) {
		log.Warn("refused agent connection: too many failed authentications from this address")
		return
	}
	if s.Draining() {
		log.Info("refused agent connection", "reason", errDraining)
		return
	}
	mux, err := transport.NewServerSession(conn, log)
	if err != nil {
		log.Warn("agent session setup failed", "error", err)
		return
	}
	defer mux.Close()

	sess := &agentSession{server: s, id: protocol.RandomID(8), remote: conn.RemoteAddr().String(), log: log, mux: mux, peer: peer, websocket: websocket}
	if !s.track(sess) {
		return
	}
	defer s.untrack(sess)
	defer sess.closeTunnels()

	if err := sess.handshake(); err != nil {
		if errors.Is(err, errUnauthorized) {
			s.authFailures.Allow(ip)
			s.counters.authFailures.Add(1)
		}
		log.Warn("agent rejected", "error", err)
		return
	}
	s.counters.sessionsAccepted.Add(1)
	sess.lastSeen.Store(time.Now().UnixNano())
	if s.clustered() {
		s.cfg.Cluster.AgentUp(sess.agentInfo(ip.String()))
		defer func() { s.cfg.Cluster.AgentDown(sess.agentID, sess.id, DisconnectReason(sess.reason.Load())) }()
	}
	s.goTracked(sess.watchdog)
	sess.controlLoop()
	sess.log.Info("agent disconnected")
}

// agentInfo describes the session for the cluster.
func (sess *agentSession) agentInfo(publicIP string) AgentInfo {
	info := AgentInfo{SessionID: sess.id, AgentID: sess.agentID, TokenID: sess.token.ID, TokenName: sess.token.Name,
		Version: sess.hello.GetAgentVersion(), OS: sess.hello.GetOs(), Arch: sess.hello.GetArch(),
		PublicIP: publicIP, WebSocket: sess.websocket, ConnectedAt: sess.connectedAt}
	if sess.peer != nil {
		if _, serial, err := auth.CertIdentity(sess.peer); err == nil {
			info.CertSerial = serial
		}
	}
	return info
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
	rec, err := sess.server.authenticate(hello.GetToken(), sess.peer)
	if err != nil {
		msg := "invalid token or certificate"
		if errors.Is(err, errCertRequired) {
			msg = "this token requires a client certificate"
		}
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED, "%s", msg))
		return fmt.Errorf("agent %q: %w", hello.GetAgentId(), err)
	}
	if hello.GetAgentId() == "" {
		sess.send(protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "agent ID is required"))
		return fmt.Errorf("hello without agent ID")
	}

	sess.tunnelsMu.Lock()
	sess.token = rec
	sess.agentID = hello.GetAgentId()
	sess.hello = hello
	sess.connectedAt = time.Now()
	sess.tunnelsMu.Unlock()
	sess.log = sess.log.With("session", sess.id, "token", rec.Name, "agent", sess.agentID)
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
			sess.rttMicros.Store(body.Ping.GetLastRttUs())
			reply = &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Pong{
				Pong: &l8tunnel.Pong{Nonce: body.Ping.GetNonce(), SentUnixNano: body.Ping.GetSentUnixNano()},
			}}
		default:
			reply = protocol.ErrorMessage(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
				"unexpected control message %T", body)
		}
		if reply == nil {
			return // the session ends; the agent reconnects
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
				sess.close(ReasonHeartbeat)
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
			var names []string
			for _, o := range opened {
				o.close()
				sess.server.registry.rollback(o.res, sess, o.existed)
				names = append(names, o.endpoint.GetName())
			}
			if sess.server.clustered() && len(names) > 0 {
				sess.server.cfg.Cluster.ReleaseTunnels(sess.id, names)
			}
			if errors.Is(err, ErrClusterUnavailable) {
				sess.log.Warn("registration deferred: the registry is unreachable; ending the session so the agent retries")
				return nil
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
	sess.tunnelsMu.Lock()
	sess.tunnels = append(sess.tunnels, opened...)
	sess.tunnelsMu.Unlock()
	for _, t := range opened {
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
	sess.tunnelsMu.Lock()
	tunnels := sess.tunnels
	sess.tunnels = nil
	sess.tunnelsMu.Unlock()
	var names []string
	for _, t := range tunnels {
		t.close()
		sess.server.registry.park(t.res, sess)
		names = append(names, t.endpoint.GetName())
	}
	if sess.server.clustered() && len(names) > 0 {
		// A revoked token's names aren't held; every other disconnect
		// keeps them for the grace period, on whichever relay the agent
		// comes back to.
		if DisconnectReason(sess.reason.Load()) == ReasonTokenRevoked {
			sess.server.cfg.Cluster.ReleaseTunnels(sess.id, names)
		} else {
			sess.server.cfg.Cluster.ParkTunnels(sess.id, names)
		}
	}
}

func (sess *agentSession) send(msg *l8tunnel.ControlMessage) error {
	sess.writeMu.Lock()
	defer sess.writeMu.Unlock()
	return protocol.WriteMessage(sess.control, msg)
}

var (
	errUnauthorized = errors.New("invalid token or certificate")
	errCertRequired = fmt.Errorf("%w: the token requires a client certificate", errUnauthorized)
)

// authenticate identifies the agent's token from its client certificate,
// its token string, or both (which must then name the same token).
func (s *Server) authenticate(token string, peer *x509.Certificate) (*auth.TokenRecord, error) {
	var byCert *auth.TokenRecord
	if peer != nil {
		id, serial, err := auth.CertIdentity(peer)
		if err != nil {
			return nil, errUnauthorized
		}
		rec, err := s.cfg.Tokens.TokenByID(id)
		if err != nil {
			return nil, fmt.Errorf("look up token: %w", err)
		}
		// The serial must still be listed: revoking the token (or its
		// certificates) takes effect on the next handshake.
		if rec == nil || !rec.HasCertSerial(serial) {
			return nil, errUnauthorized
		}
		byCert = rec
	}
	if token == "" {
		if byCert == nil {
			return nil, errUnauthorized
		}
		return byCert, nil
	}
	rec, err := s.verifyToken(token)
	if err != nil {
		return nil, err
	}
	if byCert != nil && byCert.ID != rec.ID {
		return nil, errUnauthorized
	}
	if byCert == nil && rec.Policy.RequireCert {
		return nil, errCertRequired
	}
	return rec, nil
}

// verifyToken checks a presented token against the store. Lookup is by the
// token's ID; the secret is compared with bcrypt.
func (s *Server) verifyToken(token string) (*auth.TokenRecord, error) {
	id, secret, err := auth.ParseToken(token)
	if err != nil {
		return nil, errUnauthorized
	}
	rec, err := s.cfg.Tokens.TokenByID(id)
	if err != nil {
		// A store failure is not the agent's fault; don't count it.
		return nil, fmt.Errorf("look up token: %w", err)
	}
	if rec == nil || !rec.Verify(secret) {
		return nil, errUnauthorized
	}
	return rec, nil
}
