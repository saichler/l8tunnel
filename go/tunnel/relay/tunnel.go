package relay

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
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
	listener  *net.TCPListener // TCP/SSH only
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
	if !hasPublicPort(typ) && spec.GetPublicPort() != 0 {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"public_port applies only to tcp and ssh tunnels, not %s", typ)
	}

	name := spec.GetName()
	if name == "" {
		name = "t-" + protocol.RandomID(4)
	}
	if !namePattern.MatchString(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q must be a lowercase DNS label", name)
	}
	hostname := name + "." + s.cfg.BaseDomain
	if hostname == s.cfg.ControlSNI {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q is reserved for the relay", name)
	}
	res, existed, err := s.registry.claim(name, typ, sess.token, sess.agentID, sess)
	if err != nil {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN, "tunnel name %q is taken", name)
	}

	t := &tunnel{
		server:  s,
		session: sess,
		res:     res,
		existed: existed,
		endpoint: &l8tunnel.Endpoint{
			TunnelId: protocol.RandomID(8),
			Name:     name,
			Type:     typ,
			Hostname: hostname,
		},
	}
	switch {
	case hasPublicPort(typ):
		ln, port, err := s.listenTunnelPort(res, int(spec.GetPublicPort()))
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

// httpsHost is host with the public HTTPS port, which is left out when 443.
func (s *Server) httpsHost(host string) string {
	if port := s.publicHTTPSPort(); port != 443 {
		return net.JoinHostPort(host, strconv.Itoa(port))
	}
	return host
}

// listenTunnelPort binds res's public port. A reclaimed reservation keeps
// its port unless a different one is requested; otherwise the requested
// port, or the first free port in the relay's range, is used.
func (s *Server) listenTunnelPort(res *reservation, requested int) (*net.TCPListener, int, error) {
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
		if requested < s.cfg.TCPPortMin || requested > s.cfg.TCPPortMax {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_NOT_ALLOWED,
				"port %d is outside the relay's range %d-%d", requested, s.cfg.TCPPortMin, s.cfg.TCPPortMax)
		}
		ln, err := s.tryListen(requested)
		if err != nil {
			return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
				"port %d is unavailable: %v", requested, err)
		}
		s.registry.setPort(res, requested)
		return ln, requested, nil
	}
	for port := s.cfg.TCPPortMin; port <= s.cfg.TCPPortMax; port++ {
		if ln, err := s.tryListen(port); err == nil {
			s.registry.setPort(res, port)
			return ln, port, nil
		}
	}
	return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
		"no free port in the relay's range %d-%d", s.cfg.TCPPortMin, s.cfg.TCPPortMax)
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

// openStream opens a stream to the agent and sends its header.
func (t *tunnel) openStream(clientAddr string) (*transport.Stream, error) {
	stream, err := t.session.mux.Open()
	if err != nil {
		return nil, err
	}
	open := &l8tunnel.StreamOpen{TunnelId: t.endpoint.GetTunnelId(), ClientAddr: clientAddr}
	if err := protocol.WriteMessage(stream, open); err != nil {
		stream.Close()
		return nil, err
	}
	return stream, nil
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
	res := pipe.Join(conn, stream)
	log.Debug("public connection closed", "bytes_in", res.AtoB, "bytes_out", res.BtoA, "error", res.Err)
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
