package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
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
	listener  *net.TCPListener // TCP/SSH without an access token
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
	if !namePattern.MatchString(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q must be a lowercase DNS label", name)
	}
	if !policy.AllowsName(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"token %q may not use the tunnel name %q", sess.token.Name, name)
	}
	hostname := name + "." + s.cfg.BaseDomain
	if hostname == s.cfg.ControlSNI {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q is reserved for the relay", name)
	}
	res, existed, err := s.registry.claim(name, typ, sess.token.ID, sess.agentID, sess, policy.MaxTunnels)
	switch {
	case errors.Is(err, errMaxTunnels):
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"token %q may have at most %d tunnels", sess.token.Name, policy.MaxTunnels)
	case err != nil:
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN, "tunnel name %q is taken", name)
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
		},
	}
	switch {
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

// checkAccess parses a spec's access policy and checks it fits the type.
func (s *Server) checkAccess(typ l8tunnel.TunnelType, spec *l8tunnel.TunnelSpec) (*auth.Access, error) {
	access, err := auth.ValidateSpecAccess(typ, spec.GetPublicPort(), spec.GetAccess())
	if err != nil {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST, "tunnel %q: %v", spec.GetName(), err)
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
func (s *Server) listenTunnelPort(res *reservation, requested int, policy auth.Policy) (*net.TCPListener, int, error) {
	held := s.registry.portOf(res)
	if held != 0 && (requested == 0 || requested == held) {
		ln, err := s.listen(held)
		if err != nil {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
				"port %d is unavailable: %v", held, err)
		}
		return ln, held, nil
	}
	lo, hi, ok := policy.PortRange(s.cfg.TCPPortMin, s.cfg.TCPPortMax)
	if requested != 0 {
		if requested < s.cfg.TCPPortMin || requested > s.cfg.TCPPortMax {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED,
				"port %d is outside the relay's range %d-%d", requested, s.cfg.TCPPortMin, s.cfg.TCPPortMax)
		}
		if !ok || requested < lo || requested > hi {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
				"the token's policy doesn't allow port %d (allowed: %s)", requested, policy.Ports)
		}
		ln, err := s.tryListen(requested)
		if err != nil {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
				"port %d is unavailable: %v", requested, err)
		}
		s.registry.setPort(res, requested)
		return ln, requested, nil
	}
	if !ok {
		return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN,
			"the token's port range %s doesn't overlap the relay's %d-%d", policy.Ports, s.cfg.TCPPortMin, s.cfg.TCPPortMax)
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
func (s *Server) tryListen(port int) (*net.TCPListener, error) {
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

func (s *Server) listen(port int) (*net.TCPListener, error) {
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		return nil, err
	}
	return net.ListenTCP("tcp", addr)
}

// serve accepts mode A connections on a TCP/SSH tunnel's public port.
func (t *tunnel) serve() {
	log := t.session.log.With("tunnel", t.endpoint.GetName())
	for {
		conn, err := t.listener.AcceptTCP()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			log.Warn("accept public connection failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		if !t.server.admit(conn.RemoteAddr(), t.access, log) {
			conn.Close()
			continue
		}
		t.server.goTracked(func() { t.forward(conn, conn.RemoteAddr().String()) })
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
