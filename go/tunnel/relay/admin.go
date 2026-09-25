package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"sort"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

// remoteIP extracts the IP of a TCP peer address.
func remoteIP(addr net.Addr) netip.Addr {
	if tcp, ok := addr.(*net.TCPAddr); ok {
		if ip, ok := netip.AddrFromSlice(tcp.IP); ok {
			return ip.Unmap()
		}
	}
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// admit applies the per-IP connection rate limit and, when access is set,
// the tunnel's IP allow/deny lists.
func (s *Server) admit(addr net.Addr, access *auth.Access, log *slog.Logger) bool {
	ip := remoteIP(addr)
	if !s.connLimit.Allow(ip) {
		s.counters.rejectedRate.Add(1)
		log.Debug("connection rate limit exceeded", "remote", addr.String())
		return false
	}
	if access != nil && !access.AllowsIP(ip) {
		s.counters.rejectedIP.Add(1)
		log.Debug("client IP not allowed by the tunnel's access policy", "remote", addr.String())
		return false
	}
	return true
}

// DisconnectToken releases every reservation of a revoked token and ends
// its sessions. Call it after deleting the token from the store, so the
// agents can't reconnect with it.
func (s *Server) DisconnectToken(tokenID string) int {
	sessions := map[*agentSession]struct{}{}
	for _, sess := range s.registry.releaseToken(tokenID) {
		sessions[sess] = struct{}{}
	}
	s.mu.Lock()
	for sess := range s.sessions {
		if sess.token != nil && sess.token.ID == tokenID {
			sessions[sess] = struct{}{}
		}
	}
	s.mu.Unlock()
	for sess := range sessions {
		sess.log.Info("token revoked, disconnecting agent")
		sess.mux.Close()
	}
	return len(sessions)
}

// Reserve permanently binds a tunnel name (and optionally a tcp/ssh public
// port) to a token. Call it after storing the reservation.
func (s *Server) Reserve(name, tokenID string, port int) error {
	if !namePattern.MatchString(name) {
		return fmt.Errorf("tunnel name %q must be a lowercase DNS label", name)
	}
	if name+"."+s.cfg.BaseDomain == s.cfg.ControlSNI || s.isReservedName(name) {
		return fmt.Errorf("tunnel name %q is reserved for the relay", name)
	}
	if port != 0 && (port < s.cfg.TCPPortMin || port > s.cfg.TCPPortMax) {
		return fmt.Errorf("port %d is outside the relay's range %d-%d", port, s.cfg.TCPPortMin, s.cfg.TCPPortMax)
	}
	switch err := s.registry.reserve(name, tokenID, port); {
	case errors.Is(err, errNameTaken):
		return fmt.Errorf("tunnel name %q is held by another token", name)
	case errors.Is(err, errPortTaken):
		return fmt.Errorf("port %d is held by another tunnel", port)
	case err != nil:
		return err
	}
	return nil
}

// Unreserve removes a permanent reservation. A connected tunnel keeps
// running; its name gets the normal grace period when it disconnects.
func (s *Server) Unreserve(name string) {
	s.registry.unreserve(name)
}

// Status is a snapshot of the relay for the admin API.
type Status struct {
	Sessions []SessionStatus `json:"sessions"`
	Parked   []ParkedTunnel  `json:"parked"`
}

// SessionStatus describes a connected agent.
type SessionStatus struct {
	ID          string         `json:"id"`
	Token       string         `json:"token"`
	TokenID     string         `json:"token_id"`
	AgentID     string         `json:"agent_id"`
	Remote      string         `json:"remote"`
	Version     string         `json:"version"`
	OS          string         `json:"os"`
	Arch        string         `json:"arch"`
	ConnectedAt time.Time      `json:"connected_at"`
	RTTMicros   int64          `json:"rtt_us"` // agent-reported heartbeat round trip
	Tunnels     []TunnelStatus `json:"tunnels"`
}

// TunnelStatus describes an active tunnel.
type TunnelStatus struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	PublicAddress string `json:"public_address"`
	Hostname      string `json:"hostname"`
	ActiveConns   int64  `json:"active_conns"`
	TotalConns    int64  `json:"total_conns"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
}

// Status returns a snapshot of connected agents, their tunnels, and
// reservations without a connected agent.
func (s *Server) Status() Status {
	s.mu.Lock()
	sessions := make([]*agentSession, 0, len(s.sessions))
	for sess := range s.sessions {
		sessions = append(sessions, sess)
	}
	s.mu.Unlock()

	st := Status{Sessions: []SessionStatus{}, Parked: s.registry.parked()}
	for _, sess := range sessions {
		info, ok := sess.status()
		if ok {
			st.Sessions = append(st.Sessions, info)
		}
	}
	sort.Slice(st.Sessions, func(i, j int) bool { return st.Sessions[i].ConnectedAt.Before(st.Sessions[j].ConnectedAt) })
	if st.Parked == nil {
		st.Parked = []ParkedTunnel{}
	}
	return st
}

// status describes the session; ok is false before its handshake is done.
func (sess *agentSession) status() (SessionStatus, bool) {
	sess.tunnelsMu.Lock()
	defer sess.tunnelsMu.Unlock()
	if sess.token == nil || sess.hello == nil {
		return SessionStatus{}, false
	}
	info := SessionStatus{
		ID: sess.id, Token: sess.token.Name, TokenID: sess.token.ID, AgentID: sess.agentID,
		Remote: sess.remote, Version: sess.hello.GetAgentVersion(), OS: sess.hello.GetOs(),
		Arch: sess.hello.GetArch(), ConnectedAt: sess.connectedAt, RTTMicros: sess.rttMicros.Load(),
		Tunnels: []TunnelStatus{},
	}
	for _, t := range sess.tunnels {
		info.Tunnels = append(info.Tunnels, TunnelStatus{
			Name:          t.endpoint.GetName(),
			Type:          protocol.TunnelTypeName(t.endpoint.GetType()),
			PublicAddress: t.endpoint.GetPublicAddress(),
			Hostname:      t.endpoint.GetHostname(),
			ActiveConns:   t.stats.active.Load(),
			TotalConns:    t.stats.total.Load(),
			BytesIn:       t.stats.bytesIn.Load(),
			BytesOut:      t.stats.bytesOut.Load(),
		})
	}
	return info, true
}
