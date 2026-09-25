package relay

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// listenerTLSConfig routes TLS handshakes by SNI on the shared listener:
// the control SNI offers only the l8tunnel ALPN (agents), <name>.<base>
// of an active tunnel offers no ALPN (mode B), and any other name fails
// the handshake, so clients get an error instead of an empty connection.
func (s *Server) listenerTLSConfig() *tls.Config {
	agentCfg := s.cfg.TLS.Clone()
	agentCfg.NextProtos = []string{protocol.ALPN}
	tunnelCfg := s.cfg.TLS.Clone()
	tunnelCfg.NextProtos = nil

	base := s.cfg.TLS.Clone()
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		sni := strings.ToLower(hello.ServerName)
		if sni == s.cfg.ControlSNI {
			if !offersALPN(hello.SupportedProtos) {
				return nil, fmt.Errorf("control connection without ALPN %q", protocol.ALPN)
			}
			return agentCfg, nil
		}
		if name := s.tunnelName(sni); name != "" {
			if s.registry.lookupActive(name) == nil {
				return nil, fmt.Errorf("no active tunnel %q", name)
			}
			return tunnelCfg, nil
		}
		return nil, fmt.Errorf("unknown server name %q", hello.ServerName)
	}
	return base
}

func offersALPN(protos []string) bool {
	for _, p := range protos {
		if p == protocol.ALPN {
			return true
		}
	}
	return false
}

// tunnelName extracts the tunnel name from <name>.<base-domain>, or
// returns "" when sni isn't a tunnel host name.
func (s *Server) tunnelName(sni string) string {
	name, ok := strings.CutSuffix(sni, "."+s.cfg.BaseDomain)
	if !ok || !namePattern.MatchString(name) {
		return ""
	}
	return name
}

// serveConn completes the handshake and hands the connection to the agent
// control path or to the tunnel its SNI names.
func (s *Server) serveConn(conn *tls.Conn) {
	defer conn.Close()
	log := s.log.With("remote", conn.RemoteAddr().String())

	ctx, cancel := context.WithTimeout(context.Background(), handshakeTimeout)
	err := conn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		log.Debug("TLS handshake failed", "error", err)
		return
	}

	sni := strings.ToLower(conn.ConnectionState().ServerName)
	if sni == s.cfg.ControlSNI {
		if err := transport.CheckALPN(conn); err != nil {
			log.Warn("rejected control connection", "error", err)
			return
		}
		s.serveAgent(conn, log)
		return
	}
	t := s.registry.lookupActive(s.tunnelName(sni))
	if t == nil {
		log.Debug("no active tunnel for server name", "sni", sni)
		return
	}
	t.forward(conn, conn.RemoteAddr().String())
}
