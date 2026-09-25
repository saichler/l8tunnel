package relay

import (
	"errors"
	"log/slog"
	"net"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/registry"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// DisconnectReason says why an agent session ended.
type DisconnectReason int32

const (
	ReasonAgentClosed DisconnectReason = iota
	ReasonHeartbeat
	ReasonTokenRevoked
	ReasonDrained
	ReasonTakeover
	ReasonOperator
)

// Cluster links a relay to the other relays (Kubernetes mode). A nil
// Cluster is a standalone relay, whose own registry is the only authority.
type Cluster interface {
	// ClaimTunnel registers a tunnel cluster-wide and returns its public
	// port (tcp/ssh). The error is a *protocol.RemoteError for the agent.
	ClaimTunnel(c ClaimRequest) (publicPort int, err error)
	// ParkTunnels holds a finished session's names for the grace period.
	ParkTunnels(sessionID string, names []string)
	// ReleaseTunnels frees names now.
	ReleaseTunnels(sessionID string, names []string)
	AgentUp(a AgentInfo)
	AgentDown(agentID, sessionID string, reason DisconnectReason)
	// OwnerOf returns the TLS address of the relay serving host's tunnel,
	// when another relay serves it.
	OwnerOf(host string) (addr string, ok bool)
	// StreamOwnerOf returns the stream address of the relay serving the
	// named tunnel, when another relay serves it, and whether the tunnel
	// needs an access token (gateway keys then need an explicit grant).
	StreamOwnerOf(name string) (addr string, accessToken, ok bool)
	// ForwardKey signs the PROXY headers relays and the edge exchange.
	ForwardKey() []byte
}

// ClaimRequest is one tunnel to claim cluster-wide.
type ClaimRequest struct {
	SessionID, AgentID, TokenID string
	MaxTunnels                  int
	PortMin, PortMax            int // the token's allowed range, within the relay's
	TunnelID, Name, Hostname    string
	Type                        l8tunnel.TunnelType
	Domains                     []string
	PublicPort                  int // requested; 0 = allocate
	AccessToken                 bool
}

// AgentInfo describes an authenticated agent session.
type AgentInfo struct {
	SessionID, AgentID, TokenID, TokenName, CertSerial string
	Version, OS, Arch, PublicIP                        string
	WebSocket                                          bool
	ConnectedAt                                        time.Time
}

// claimInCluster claims one tunnel through the Cluster.
func (s *Server) claimInCluster(sess *agentSession, t *tunnel, spec *l8tunnel.TunnelSpec, policy auth.Policy) (int, error) {
	requested := int(spec.GetPublicPort())
	if requested != 0 && hasPublicPort(t.endpoint.GetType()) {
		switch err := s.rules.CheckRequestedPort(requested, policy); {
		case errors.Is(err, registry.ErrPortOutsideRange):
			return 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED, "%v", err)
		case err != nil:
			return 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN, "%v", err)
		}
	}
	lo, hi, err := s.rules.AllocationRange(policy)
	if err != nil && hasPublicPort(t.endpoint.GetType()) {
		return 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN, "%v", err)
	}
	return s.cfg.Cluster.ClaimTunnel(ClaimRequest{
		SessionID: sess.id, AgentID: sess.agentID, TokenID: sess.token.ID, MaxTunnels: policy.MaxTunnels,
		PortMin: lo, PortMax: hi, TunnelID: t.endpoint.GetTunnelId(), Name: t.endpoint.GetName(),
		Hostname: t.endpoint.GetHostname(), Type: t.endpoint.GetType(), Domains: t.endpoint.GetDomains(),
		PublicPort: requested, AccessToken: t.access.RequiresToken(),
	})
}

// setEndpointAddress fills a tunnel's public address in cluster mode.
func (s *Server) setEndpointAddress(t *tunnel, port int) {
	host := t.endpoint.GetHostname()
	switch {
	case hasPublicPort(t.endpoint.GetType()) && !t.access.RequiresToken():
		t.endpoint.PublicPort = uint32(port)
		t.endpoint.PublicAddress = net.JoinHostPort(s.cfg.PublicHost, strconv.Itoa(port))
	case t.endpoint.GetType() == l8tunnel.TunnelType_TUNNEL_TYPE_HTTP:
		t.endpoint.PublicAddress = "https://" + s.httpsHost(host)
	default:
		t.endpoint.PublicAddress = net.JoinHostPort(host, strconv.Itoa(s.publicHTTPSPort()))
	}
}

// clustered reports whether the relay runs in cluster mode.
func (s *Server) clustered() bool {
	return s.cfg.Cluster != nil
}

// serveStream serves the stream port: the edge (mode A) and other relays
// (the SSH gateway) send a raw stream for a named tunnel, with a signed
// PROXY header. A stream for a tunnel this relay doesn't serve is refused:
// there is no second hop.
func (s *Server) serveStream(conn net.Conn) {
	defer conn.Close()
	log := s.log.With("remote", conn.RemoteAddr().String(), "component", "stream")
	conn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	client := conn.RemoteAddr().String() // reads the PROXY header
	name, err := transport.VerifySignedTLVs(s.cfg.Cluster.ForwardKey(), transport.ProxyTLVs(conn), client, time.Now())
	if err != nil {
		log.Warn("refused stream", "error", err)
		return
	}
	conn.SetReadDeadline(time.Time{})
	t, _, _ := s.registry.lookup(name)
	if t == nil {
		s.counters.rejectedNoRoute.Add(1)
		log.Debug("stream for a tunnel this relay doesn't serve", "tunnel", name)
		return
	}
	pc, ok := conn.(pipe.Conn)
	if !ok || !s.admit(conn.RemoteAddr(), t.access, log) {
		return
	}
	t.forward(pc, client)
}

// forwardToOwner passes a connection for another relay's tunnel to that
// relay, keeping the client's address in a signed PROXY header. A
// connection that was itself forwarded isn't forwarded again.
func (s *Server) forwardToOwner(conn net.Conn, raw net.Conn, host string, log *slog.Logger) bool {
	if !s.clustered() {
		return false
	}
	if _, forwarded := transport.FindTLV(transport.ProxyTLVs(raw), transport.TLVAuth); forwarded {
		return false
	}
	addr, ok := s.cfg.Cluster.OwnerOf(host)
	if !ok {
		return false
	}
	up, err := net.DialTimeout("tcp", addr, handshakeTimeout)
	if err != nil {
		log.Warn("forward to the owning relay failed", "host", host, "relay", addr, "error", err)
		return false
	}
	client := raw.RemoteAddr()
	tlvs := transport.SignedTLVs(s.cfg.Cluster.ForwardKey(), host, client.String(), time.Now())
	if err := transport.WriteProxyHeader(up, client, up.RemoteAddr(), tlvs...); err != nil {
		up.Close()
		return false
	}
	raw.SetReadDeadline(time.Time{})
	pc, ok := conn.(pipe.Conn)
	if !ok {
		up.Close()
		return false
	}
	pipe.Join(pc, up.(*net.TCPConn))
	return true
}

// Drain stops taking agents and closes the current sessions one by one,
// pace apart; the agents reconnect (through the edge) to other relays.
func (s *Server) Drain(pace time.Duration) {
	if !s.draining.CompareAndSwap(false, true) {
		return
	}
	s.log.Info("draining: closing agent sessions")
	go func() {
		for _, sess := range s.sessionList() {
			if !s.draining.Load() {
				return
			}
			sess.close(ReasonDrained)
			time.Sleep(pace)
		}
	}()
}

// Resume takes agents again after a drain.
func (s *Server) Resume() {
	if s.draining.CompareAndSwap(true, false) {
		s.log.Info("resumed: taking agent sessions again")
	}
}

// Draining reports whether the relay is draining.
func (s *Server) Draining() bool {
	return s.draining.Load()
}

// DisconnectAgent closes the sessions of an agent ID; the agent reconnects
// unless its token was revoked.
func (s *Server) DisconnectAgent(agentID string, reason DisconnectReason) int {
	n := 0
	for _, sess := range s.sessionList() {
		if sess.agentID == agentID {
			sess.close(reason)
			n++
		}
	}
	return n
}

// CloseTunnel closes the session serving a tunnel ID (a takeover by another
// relay, or an operator's disconnect).
func (s *Server) CloseTunnel(tunnelID string, reason DisconnectReason) bool {
	for _, sess := range s.sessionList() {
		sess.tunnelsMu.Lock()
		found := false
		for _, t := range sess.tunnels {
			found = found || t.endpoint.GetTunnelId() == tunnelID
		}
		sess.tunnelsMu.Unlock()
		if found {
			sess.close(reason)
			return true
		}
	}
	return false
}

func (s *Server) sessionList() []*agentSession {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*agentSession, 0, len(s.sessions))
	for sess := range s.sessions {
		out = append(out, sess)
	}
	return out
}

// close ends the session, recording why.
func (sess *agentSession) close(reason DisconnectReason) {
	sess.reason.CompareAndSwap(int32(ReasonAgentClosed), int32(reason))
	sess.mux.Close()
}

// ErrClusterUnavailable is what a Cluster returns when it can't reach the
// registry. The relay then ends the session instead of refusing the
// tunnels, because agents treat a refusal as final; they reconnect with
// their normal backoff and register again.
var ErrClusterUnavailable = errors.New("the cluster registry is unavailable")

// errDraining refuses agents while the relay drains.
var errDraining = errors.New("the relay is draining")

// drainingFlag is embedded in Server.
type drainingFlag struct {
	draining atomic.Bool
}
