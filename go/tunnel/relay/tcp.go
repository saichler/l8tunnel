package relay

import (
	"errors"
	"fmt"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// tcpTunnel serves one TCP/SSH tunnel's public port.
type tcpTunnel struct {
	server    *Server
	session   *agentSession
	endpoint  *l8tunnel.Endpoint
	listener  *net.TCPListener
	port      int
	closeOnce sync.Once
}

func remoteErr(code l8tunnel.ErrorCode, format string, args ...interface{}) error {
	return &protocol.RemoteError{Code: code, Message: fmt.Sprintf(format, args...)}
}

// openTunnel validates spec, reserves its name and public port, and
// starts listening. The caller starts serving it.
func (s *Server) openTunnel(sess *agentSession, spec *l8tunnel.TunnelSpec) (*tcpTunnel, error) {
	switch spec.GetType() {
	case l8tunnel.TunnelType_TUNNEL_TYPE_TCP, l8tunnel.TunnelType_TUNNEL_TYPE_SSH:
	case l8tunnel.TunnelType_TUNNEL_TYPE_HTTP, l8tunnel.TunnelType_TUNNEL_TYPE_TLS:
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_UNSUPPORTED_TUNNEL_TYPE,
			"tunnel type %s is not supported by this relay yet", spec.GetType())
	default:
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"invalid tunnel type %s", spec.GetType())
	}

	name := spec.GetName()
	if name == "" {
		name = "t-" + protocol.RandomID(4)
	}
	if !namePattern.MatchString(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST,
			"tunnel name %q must be a lowercase DNS label", name)
	}
	if !s.registry.reserveName(name) {
		return nil, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN, "tunnel name %q is taken", name)
	}

	ln, port, err := s.listenTunnelPort(int(spec.GetPublicPort()))
	if err != nil {
		s.registry.releaseName(name)
		return nil, err
	}
	return &tcpTunnel{
		server:   s,
		session:  sess,
		listener: ln,
		port:     port,
		endpoint: &l8tunnel.Endpoint{
			TunnelId:      protocol.RandomID(8),
			Name:          name,
			Type:          spec.GetType(),
			PublicAddress: net.JoinHostPort(s.cfg.PublicHost, strconv.Itoa(port)),
			PublicPort:    uint32(port),
		},
	}, nil
}

// listenTunnelPort binds the requested port, or the first free port in the
// relay's range when requested is 0.
func (s *Server) listenTunnelPort(requested int) (*net.TCPListener, int, error) {
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
		return ln, requested, nil
	}
	for port := s.cfg.TCPPortMin; port <= s.cfg.TCPPortMax; port++ {
		if ln, err := s.tryListen(port); err == nil {
			return ln, port, nil
		}
	}
	return nil, 0, remoteErr(l8tunnel.ErrorCode_ERROR_CODE_PORT_UNAVAILABLE,
		"no free port in the relay's range %d-%d", s.cfg.TCPPortMin, s.cfg.TCPPortMax)
}

func (s *Server) tryListen(port int) (*net.TCPListener, error) {
	if !s.registry.reservePort(port) {
		return nil, fmt.Errorf("port %d is used by another tunnel", port)
	}
	addr, err := net.ResolveTCPAddr("tcp", net.JoinHostPort(s.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		s.registry.releasePort(port)
		return nil, err
	}
	ln, err := net.ListenTCP("tcp", addr)
	if err != nil {
		s.registry.releasePort(port)
		return nil, err
	}
	return ln, nil
}

func (t *tcpTunnel) serve() {
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
		t.server.goTracked(func() { t.forward(conn) })
	}
}

// forward carries one public connection to the agent over a new stream.
func (t *tcpTunnel) forward(conn *net.TCPConn) {
	log := t.session.log.With("tunnel", t.endpoint.GetName(), "client", conn.RemoteAddr().String())
	stream, err := t.session.mux.Open()
	if err != nil {
		log.Warn("open stream to agent failed", "error", err)
		conn.Close()
		return
	}
	open := &l8tunnel.StreamOpen{TunnelId: t.endpoint.GetTunnelId(), ClientAddr: conn.RemoteAddr().String()}
	if err := protocol.WriteMessage(stream, open); err != nil {
		log.Warn("send stream header failed", "error", err)
		stream.Close()
		conn.Close()
		return
	}
	res := pipe.Join(conn, stream)
	log.Debug("public connection closed", "bytes_in", res.AtoB, "bytes_out", res.BtoA, "error", res.Err)
}

// close stops accepting public connections and frees the name and port.
// Connections already in flight end when the agent session closes.
func (t *tcpTunnel) close() {
	t.closeOnce.Do(func() {
		t.listener.Close()
		t.server.registry.releasePort(t.port)
		t.server.registry.releaseName(t.endpoint.GetName())
	})
}
