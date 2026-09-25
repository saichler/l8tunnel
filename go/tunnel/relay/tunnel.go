package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/registry"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// tunnel is one registered tunnel. Every type is reachable by SNI on the
// shared TLS listener as <name>.<base-domain>; TCP/SSH tunnels also get a
// dedicated public port (mode A).
type tunnel struct {
	server    *Server
	session   *agentSession
	res       *reservation
	existed   bool // the reservation was reclaimed, not newly created
	endpoint  *l8tunnel.Endpoint
	listener  net.Listener // TCP/SSH without an access token
	access    *auth.Access
	stats     tunnelStats
	closeOnce sync.Once
}

func remoteErr(code l8tunnel.ErrorCode, format string, args ...interface{}) error {
	return &protocol.RemoteError{Code: code, Message: fmt.Sprintf(format, args...)}
}

func hasPublicPort(typ l8tunnel.TunnelType) bool {
	return typ == l8tunnel.TunnelType_TUNNEL_TYPE_TCP || typ == l8tunnel.TunnelType_TUNNEL_TYPE_SSH
}

// openTunnel validates spec, claims its name (and public port for TCP/SSH)
// and starts listening. The caller starts serving it.
func (s *Server) openTunnel(sess *agentSession, spec *l8tunnel.TunnelSpec) (*tunnel, error) {
	typ := spec.GetType()
	switch typ {
	case l8tunnel.TunnelType_TUNNEL_TYPE_TCP, l8tunnel.TunnelType_TUNNEL_TYPE_SSH,
		l8tunnel.TunnelType_TUNNEL_TYPE_HTTP, l8tunnel.TunnelType_TUNNEL_TYPE_TLS:
	default:
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "invalid tunnel type %s", typ)
	}
	policy := sess.token.Policy
	if !policy.AllowsType(protocol.TunnelTypeName(typ)) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"token %q may not register %s tunnels", sess.token.Name, protocol.TunnelTypeName(typ))
	}
	access, err := s.checkAccess(typ, spec)
	if err != nil {
		return nil, err
	}

	name := spec.GetName()
	if name == "" {
		name = "t-" + protocol.RandomID(4)
	}
	if !registry.ValidName(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q must be a lowercase DNS label", name)
	}
	if !policy.AllowsName(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"token %q may not use the tunnel name %q", sess.token.Name, name)
	}
	hostname := name + "." + s.cfg.BaseDomain
	if s.rules.IsReserved(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q is reserved for the relay", name)
	}
	domains, err := s.checkDomains(sess, typ, spec)
	if err != nil {
		return nil, err
	}
	res, existed, err := s.registry.claim(name, typ, sess.token.ID, sess.agentID, sess, policy.MaxTunnels)
	switch {
	case errors.Is(err, registry.ErrMaxTunnels):
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"token %q may have at most %d tunnels", sess.token.Name, policy.MaxTunnels)
	case err != nil:
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN, "tunnel name %q is taken", name)
	}
	if err := s.registry.setDomains(res, domains); err != nil {
		s.registry.rollback(res, sess, existed)
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN, "%v", err)
	}

	t := &tunnel{
		server:  s,
		session: sess,
		res:     res,
		existed: existed,
		access:  access,
		endpoint: &l8tunnel.Endpoint{
			TunnelId: protocol.RandomID(8),
			Name:     name,
			Type:     typ,
			Hostname: hostname,
			Domains:  domains,
		},
	}
	switch {
	case s.clustered():
		// The registry checks and allocates cluster-wide; the edge forwards
		// mode A ports to this relay's stream port, so nothing listens here.
		port, err := s.claimInCluster(sess, t, spec, policy)
		if err != nil {
			s.registry.rollback(res, sess, existed)
			return nil, err
		}
		s.setEndpointAddress(t, port)
	case hasPublicPort(typ) && !access.RequiresToken():
		ln, port, err := s.listenTunnelPort(res, int(spec.GetPublicPort()), policy)
		if err != nil {
			s.registry.rollback(res, sess, existed)
			return nil, err
		}
		t.listener = ln
		t.endpoint.PublicPort = uint32(port)
		t.endpoint.PublicAddress = net.JoinHostPort(s.cfg.PublicHost, strconv.Itoa(port))
	case typ == l8tunnel.TunnelType_TUNNEL_TYPE_HTTP:
		t.endpoint.PublicAddress = "https://" + s.httpsHost(hostname)
	default:
		t.endpoint.PublicAddress = net.JoinHostPort(hostname, strconv.Itoa(s.publicHTTPSPort()))
	}
	s.registry.activate(res, t)
	return t, nil
}

// checkDomains validates a spec's custom domains: HTTP/TLS tunnels only,
// allowed by the token's policy, not under the base domain, and (for HTTP,
// where the relay terminates TLS) coverable by the relay's certificates.
func (s *Server) checkDomains(sess *agentSession, typ l8tunnel.TunnelType, spec *l8tunnel.TunnelSpec) ([]string, error) {
	if len(spec.GetDomains()) == 0 {
		return nil, nil
	}
	invalid := func(format string, args ...interface{}) error {
		return remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, format, args...)
	}
	if typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP && typ != l8tunnel.TunnelType_TUNNEL_TYPE_TLS {
		return nil, invalid("custom domains apply only to http and tls tunnels")
	}
	seen := map[string]bool{}
	var out []string
	for _, raw := range spec.GetDomains() {
		d, err := protocol.NormalizeDomain(raw)
		if err != nil {
			return nil, invalid("%v", err)
		}
		if d == s.cfg.BaseDomain || strings.HasSuffix(d, "."+s.cfg.BaseDomain) || d == s.cfg.ControlSNI {
			return nil, invalid("domain %s is under the relay's base domain; use the tunnel name instead", d)
		}
		if !sess.token.Policy.AllowsDomain(d) {
			return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
				"token %q may not serve the domain %s", sess.token.Name, d)
		}
		if typ == l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
			if err := s.cfg.CanServeHost(d); err != nil {
				return nil, invalid("domain %s: %v", d, err)
			}
		}
		if !seen[d] {
			seen[d] = true
			out = append(out, d)
		}
	}
	return out, nil
}

// checkAccess parses a spec's access policy and checks it fits the type.
func (s *Server) checkAccess(typ l8tunnel.TunnelType, spec *l8tunnel.TunnelSpec) (*auth.Access, error) {
	access, err := auth.ValidateSpecAccess(typ, spec.GetPublicPort(), spec.GetAccess())
	if err != nil {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "tunnel %q: %v", spec.GetName(), err)
	}
	if rule := access.OIDC(); rule != nil && (s.cfg.Login == nil || !s.cfg.Login.HasProvider(rule.Provider)) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel %q: the relay has no OIDC provider %q", spec.GetName(), rule.Provider)
	}
	return access, nil
}

// httpsHost is host with the public HTTPS port, which is left out when 443.
func (s *Server) httpsHost(host string) string {
	if port := s.publicHTTPSPort(); port != 443 {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return host
}

// listenTunnelPort binds res's public port. A reclaimed or operator
// reservation keeps its port unless a different one is requested;
// otherwise the requested port, or the first free port in the relay's
// range (narrowed by the token's policy), is used.
func (s *Server) listenTunnelPort(res *reservation, requested int, policy auth.Policy) (net.Listener, int, error) {
	held := s.registry.portOf(res)
	if held != 0 && (requested == 0 || requested == held) {
		ln, err := s.listen(held)
		if err != nil {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
				"port %d is unavailable: %v", held, err)
		}
		return ln, held, nil
	}
	if requested != 0 {
		switch err := s.rules.CheckRequestedPort(requested, policy); {
		case errors.Is(err, registry.ErrPortOutsideRange):
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED, "%v", err)
		case err != nil:
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN, "%v", err)
		}
		ln, err := s.tryListen(requested)
		if err != nil {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
				"port %d is unavailable: %v", requested, err)
		}
		s.registry.setPort(res, requested)
		return ln, requested, nil
	}
	lo, hi, err := s.rules.AllocationRange(policy)
	if err != nil {
		return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN, "%v", err)
	}
	for port := lo; port <= hi; port++ {
		if ln, err := s.tryListen(port); err == nil {
			s.registry.setPort(res, port)
			return ln, port, nil
		}
	}
	return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
		"no free port in the range %d-%d", lo, hi)
}

// tryListen reserves port in the registry and binds it.
func (s *Server) tryListen(port int) (net.Listener, error) {
	if !s.registry.reservePort(port) {
		return nil, fmt.Errorf("port %d is held by another tunnel", port)
	}
	ln, err := s.listen(port)
	if err != nil {
		s.registry.releasePort(port)
		return nil, err
	}
	return ln, nil
}

func (s *Server) listen(port int) (net.Listener, error) {
	ln, err := net.Listen("tcp", net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return transport.ProxyProtocolListener(ln, s.cfg.TrustedProxies), nil
}

// serve accepts mode A connections on a TCP/SSH tunnel's public port.
func (t *tunnel) serve() {
	log := t.session.log.With("tunnel", t.endpoint.GetName())
	for {
		accepted, err := t.listener.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn("accept public connection failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		conn, ok := accepted.(pipe.Conn)
		if !ok || !t.server.admit(accepted.RemoteAddr(), t.access, log) {
			accepted.Close()
			continue
		}
		t.server.goTracked(func() { t.forward(conn, accepted.RemoteAddr().String()) })
	}
}

// ID implements httpproxy.Tunnel.
func (t *tunnel) ID() string {
	return t.endpoint.GetTunnelId()
}

// OpenStream implements httpproxy.Tunnel.
func (t *tunnel) OpenStream(_ context.Context, clientAddr string) (net.Conn, error) {
	return t.openStream(clientAddr)
}

// Access implements httpproxy.Tunnel.
func (t *tunnel) Access() *auth.Access {
	return t.access
}

// openStream opens a stream to the agent, sends its header, and counts it
// in the tunnel's statistics.
func (t *tunnel) openStream(clientAddr string) (*countedStream, error) {
	stream, err := t.session.mux.Open()
	if err != nil {
		return nil, err
	}
	open := &l8tunnel.StreamOpen{TunnelId: t.endpoint.GetTunnelId(), ClientAddr: clientAddr}
	if err := protocol.WriteMessage(stream, open); err != nil {
		stream.Close()
		return nil, err
	}
	return t.stats.track(stream), nil
}

// forward carries one public connection to the agent over a new stream.
func (t *tunnel) forward(conn pipe.Conn, clientAddr string) {
	log := t.session.log.With("tunnel", t.endpoint.GetName(), "client", clientAddr)
	stream, err := t.openStream(clientAddr)
	if err != nil {
		log.Warn("open stream to agent failed", "error", err)
		conn.Close()
		return
	}
	start := time.Now()
	res := pipe.Join(conn, stream)
	log.Info("connection closed", "duration_ms", time.Since(start).Milliseconds(),
		"bytes_in", res.AtoB, "bytes_out", res.BtoA, "error", res.Err)
}

// close stops accepting mode A connections and drops cached HTTP
// connections. The name and port stay in the registry until the
// reservation is parked, released or expires. Connections in flight end
// when the agent session closes.
func (t *tunnel) close() {
	t.closeOnce.Do(func() {
		if t.listener != nil {
			t.listener.Close()
		}
		t.server.http.Forget(t.ID())
	})
}
