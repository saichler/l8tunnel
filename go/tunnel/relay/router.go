package relay

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"log/slog"
	"net"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/sni"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// routeConfigs are the TLS configs the router terminates with, per route.
type routeConfigs struct {
	agent       *tls.Config // control SNI: l8tunnel ALPN only, TLS 1.3
	agentWS     *tls.Config // control SNI over WebSocket: http/1.1, TLS 1.3
	tunnel      *tls.Config // mode B TCP/SSH: no ALPN, TLS 1.3
	tunnelToken *tls.Config // mode B with an access token: connect-token ALPN
	http        *tls.Config // HTTP tunnels and error pages: h2 + http/1.1
	reject      *tls.Config // fails every handshake with an alert
}

var errRejected = errors.New("no route for this server name")

func newRouteConfigs(base *tls.Config, agentCA *x509.Certificate) routeConfigs {
	agent := base.Clone()
	agent.MinVersion = tls.VersionTLS13
	agent.NextProtos = []string{protocol.ALPN}
	if agentCA != nil {
		// Agents may present a client certificate from the agent CA; TLS
		// verifies the chain, the relay then checks the token and serial.
		pool := x509.NewCertPool()
		pool.AddCert(agentCA)
		agent.ClientCAs = pool
		agent.ClientAuth = tls.VerifyClientCertIfGiven
	}

	agentWS := agent.Clone()
	agentWS.NextProtos = []string{"http/1.1"}

	tunnel := base.Clone()
	tunnel.MinVersion = tls.VersionTLS13
	tunnel.NextProtos = nil

	tunnelToken := tunnel.Clone()
	tunnelToken.NextProtos = []string{protocol.ConnectTokenALPN}

	http := base.Clone()
	http.MinVersion = tls.VersionTLS12
	http.NextProtos = []string{"h2", "http/1.1"}

	reject := &tls.Config{
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, errRejected },
	}
	return routeConfigs{agent: agent, agentWS: agentWS, tunnel: tunnel, tunnelToken: tunnelToken, http: http, reject: reject}
}

func offers(protos []string, want ...string) bool {
	for _, p := range protos {
		for _, w := range want {
			if p == w {
				return true
			}
		}
	}
	return false
}

// serveConn routes a connection on the shared listener by the SNI and ALPN
// of its ClientHello, which is read without being consumed:
//
//   - control SNI with the l8tunnel ALPN: an agent session
//   - an active TLS tunnel: the raw TLS stream is forwarded (passthrough)
//   - an active TCP/SSH tunnel: TLS is terminated and the inner stream
//     forwarded (mode B)
//   - an HTTP tunnel, or any other tunnel host name unless the client is
//     "l8tunnel connect": TLS is terminated and the HTTP proxy serves it
//     (or its error page)
//   - anything else: the handshake fails with an alert, so l8tunnel
//     connect gets an error instead of an empty connection
func (s *Server) serveConn(raw net.Conn) {
	handedOff := false
	defer func() {
		if !handedOff {
			raw.Close()
		}
	}()
	log := s.log.With("remote", raw.RemoteAddr().String())
	if !s.admit(raw.RemoteAddr(), nil, log) {
		return
	}
	raw.SetReadDeadline(time.Now().Add(handshakeTimeout))

	hello, conn, err := sni.Peek(raw)
	if err != nil {
		log.Debug("no TLS ClientHello", "error", err)
		return
	}
	sni := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	if sni == s.cfg.ControlSNI {
		if !offers(hello.SupportedProtos, protocol.ALPN) && offers(hello.SupportedProtos, "http/1.1") {
			// An agent using the WebSocket transport.
			if tconn := s.terminate(conn, s.routes.agentWS, log); tconn != nil {
				s.wsListener.Push(tconn)
				handedOff = true
			}
			return
		}
		if !offers(hello.SupportedProtos, protocol.ALPN) {
			s.reject(conn, log, "control SNI without the l8tunnel or http/1.1 ALPN")
			return
		}
		if tconn := s.terminate(conn, s.routes.agent, log); tconn != nil {
			if err := transport.CheckALPN(tconn); err != nil {
				log.Warn("rejected control connection", "error", err)
				return
			}
			s.serveAgent(tconn, log, peerCert(tconn.ConnectionState()))
		}
		return
	}

	if s.cfg.Login != nil && sni == s.cfg.Login.AuthHost() {
		if tconn := s.terminate(conn, s.routes.http, log); tconn != nil {
			s.http.ServeConn(tconn)
			handedOff = true
		}
		return
	}
	t, typ, name := s.resolveHost(sni)
	switch {
	case t != nil && !t.access.AllowsIP(remoteIP(raw.RemoteAddr())) && typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP:
		s.counters.rejectedIP.Add(1)
		s.reject(conn, log, "client IP not allowed by tunnel "+name)
	case t != nil && typ == l8tunnel.TunnelType_TUNNEL_TYPE_TLS:
		raw.SetReadDeadline(time.Time{})
		t.forward(conn, raw.RemoteAddr().String())
	case t != nil && hasPublicPort(typ) && t.access.RequiresToken():
		s.serveTokenTunnel(t, hello, conn, log)
	case t != nil && hasPublicPort(typ):
		if tconn := s.terminate(conn, s.routes.tunnel, log); tconn != nil {
			t.forward(tconn, raw.RemoteAddr().String())
		}
	case name != "" && (typ == l8tunnel.TunnelType_TUNNEL_TYPE_HTTP || !offers(hello.SupportedProtos, protocol.ConnectALPN)):
		if tconn := s.terminate(conn, s.routes.http, log); tconn != nil {
			s.http.ServeConn(tconn)
			handedOff = true
		}
	default:
		s.counters.rejectedNoRoute.Add(1)
		s.reject(conn, log, "no tunnel for server name "+sni)
	}
}

// terminate completes a TLS handshake with cfg and clears the read
// deadline set for the handshake. It returns nil if the handshake fails.
func (s *Server) terminate(conn *sni.Conn, cfg *tls.Config, log *slog.Logger) *tls.Conn {
	tconn := tls.Server(conn, cfg)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := tconn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		log.Debug("TLS handshake failed", "error", err)
		return nil
	}
	conn.SetReadDeadline(time.Time{})
	return tconn
}

// reject fails the handshake with an alert.
func (s *Server) reject(conn *sni.Conn, log *slog.Logger, why string) {
	log.Debug("rejected TLS connection", "reason", why)
	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	defer cancel()
	tls.Server(conn, s.routes.reject).HandshakeContext(ctx)
}

// resolveHost maps an SNI or Host name to its tunnel. name is the
// reservation's name ("" when host is neither <name>.<base-domain> nor a
// reserved custom domain); t is nil while the reservation is parked or
// when <name> isn't reserved.
func (s *Server) resolveHost(host string) (t *tunnel, typ l8tunnel.TunnelType, name string) {
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	if name = s.rules.TunnelName(host); name != "" {
		t, typ, _ = s.registry.lookup(name)
		return t, typ, name
	}
	t, typ, name, _ = s.registry.lookupDomain(host)
	return t, typ, name
}

// lookupHTTP resolves a host for the HTTP proxy.
func (s *Server) lookupHTTP(host string) (httpproxy.Tunnel, httpproxy.State, string) {
	t, typ, name := s.resolveHost(host)
	_, _, found := s.registry.lookup(name)
	switch {
	case name == "":
		return nil, httpproxy.StateUnknown, ""
	case !found || typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP:
		return nil, httpproxy.StateUnknown, name
	case t == nil:
		return nil, httpproxy.StateOffline, name
	}
	return t, httpproxy.StateActive, name
}

// IsTunnelHost reports whether host is <name>.<base-domain> for a reserved
// name, or a reserved custom domain. It is the policy for on-demand ACME
// certificates.
func (s *Server) IsTunnelHost(host string) bool {
	if s.cfg.Login != nil && strings.ToLower(host) == s.cfg.Login.AuthHost() {
		return true
	}
	_, _, name := s.resolveHost(host)
	_, _, found := s.registry.lookup(name)
	return found
}

// peerCert is the client certificate of a TLS connection, if any.
func peerCert(cs tls.ConnectionState) *x509.Certificate {
	if len(cs.PeerCertificates) == 0 {
		return nil
	}
	return cs.PeerCertificates[0]
}

// serveTokenTunnel serves mode B for a tunnel that requires an access
// token: the client must negotiate the connect-token ALPN and send a
// ConnectAuth with the right token before any data is forwarded.
func (s *Server) serveTokenTunnel(t *tunnel, hello *tls.ClientHelloInfo, conn *sni.Conn, log *slog.Logger) {
	ip := remoteIP(conn.RemoteAddr())
	if s.authFailures.Exhausted(ip) {
		s.reject(conn, log, "too many failed access tokens from this address")
		return
	}
	if !offers(hello.SupportedProtos, protocol.ConnectTokenALPN) {
		s.reject(conn, log, "tunnel "+t.endpoint.GetName()+" requires an access token")
		return
	}
	tconn := s.terminate(conn, s.routes.tunnelToken, log)
	if tconn == nil {
		return
	}
	tconn.SetReadDeadline(time.Now().Add(handshakeTimeout))
	msg := &l8tunnel.ConnectAuth{}
	if err := protocol.ReadMessage(tconn, msg); err != nil {
		log.Debug("no access token from client", "error", err)
		return
	}
	ok := t.access.CheckToken(msg.GetAccessToken())
	if err := protocol.WriteMessage(tconn, &l8tunnel.ConnectAuthResult{Ok: ok}); err != nil {
		return
	}
	if !ok {
		s.authFailures.Allow(ip)
		s.counters.authFailures.Add(1)
		log.Warn("wrong access token for tunnel", "tunnel", t.endpoint.GetName())
		return
	}
	tconn.SetReadDeadline(time.Time{})
	t.forward(tconn, conn.RemoteAddr().String())
}

// OIDCRuleFor returns the OIDC rule of the active HTTP tunnel serving
// host, or nil (oidc.Binding.RuleFor).
func (s *Server) OIDCRuleFor(host string) *auth.OIDCRule {
	t, typ, _ := s.resolveHost(host)
	if t == nil || typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
		return nil
	}
	return t.access.OIDC()
}
