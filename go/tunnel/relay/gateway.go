package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/pipe"
)

// GatewayKeyStore looks up SSH gateway keys by fingerprint; it returns nil
// (and no error) for an unknown key. store.Store implements it.
type GatewayKeyStore interface {
	GatewayKeyByFingerprint(fp string) (*auth.GatewayKey, error)
}

// GatewayConfig enables the SSH jump gateway (mode C): plain OpenSSH
// clients reach tunnels with "ssh -J gw@relay:port user@<tunnel>".
type GatewayConfig struct {
	// Listen is the gateway's address, e.g. ":2222".
	Listen  string
	HostKey ssh.Signer
	Keys    GatewayKeyStore
}

// directTCPIP is the payload of a "direct-tcpip" channel (RFC 4254 7.2).
type directTCPIP struct {
	Host       string
	Port       uint32
	OriginHost string
	OriginPort uint32
}

func (s *Server) gatewaySSHConfig() *ssh.ServerConfig {
	cfg := &ssh.ServerConfig{
		ServerVersion: "SSH-2.0-l8tunnel-gateway",
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			fp := ssh.FingerprintSHA256(key)
			k, err := s.cfg.SSHGateway.Keys.GatewayKeyByFingerprint(fp)
			if err != nil || k == nil {
				return nil, fmt.Errorf("unknown key %s", fp)
			}
			return &ssh.Permissions{Extensions: map[string]string{"fingerprint": fp, "name": k.Name}}, nil
		},
	}
	cfg.AddHostKey(s.cfg.SSHGateway.HostKey)
	return cfg
}

func (s *Server) acceptGateway(ln net.Listener, cfg *ssh.ServerConfig) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept gateway connection failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.goTracked(func() { s.serveGateway(conn, cfg) })
	}
}

// serveGateway runs one SSH connection: it authenticates the key and
// forwards direct-tcpip channels to tunnels. Nothing else is offered.
func (s *Server) serveGateway(conn net.Conn, cfg *ssh.ServerConfig) {
	defer conn.Close()
	log := s.log.With("remote", conn.RemoteAddr().String(), "component", "ssh-gateway")
	ip := remoteIP(conn.RemoteAddr())
	if !s.admit(conn.RemoteAddr(), nil, log) {
		return
	}
	if s.authFailures.Exhausted(ip) {
		log.Warn("refused gateway connection: too many failed authentications from this address")
		return
	}
	conn.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(conn, cfg)
	if err != nil {
		if !errors.Is(err, net.ErrClosed) {
			s.authFailures.Allow(ip)
			s.counters.authFailures.Add(1)
		}
		log.Debug("gateway handshake failed", "error", err)
		return
	}
	conn.SetDeadline(time.Time{})
	defer sconn.Close()
	s.trackGateway(sconn)
	defer s.untrackGateway(sconn)
	log = log.With("key", sconn.Permissions.Extensions["name"])
	log.Info("gateway login")
	go ssh.DiscardRequests(reqs)
	for newCh := range chans {
		if newCh.ChannelType() != "direct-tcpip" {
			newCh.Reject(ssh.Prohibited, "this gateway only forwards connections: use ssh -J")
			continue
		}
		s.goTracked(func() { s.gatewayChannel(sconn, newCh, log) })
	}
}

func (s *Server) gatewayChannel(sconn *ssh.ServerConn, newCh ssh.NewChannel, log *slog.Logger) {
	var req directTCPIP
	if err := ssh.Unmarshal(newCh.ExtraData(), &req); err != nil {
		newCh.Reject(ssh.ConnectionFailed, "malformed request")
		return
	}
	t, reason := s.gatewayTarget(sconn, req)
	if t == nil {
		log.Info("gateway forward refused", "target", net.JoinHostPort(req.Host, strconv.Itoa(int(req.Port))), "reason", reason)
		newCh.Reject(ssh.Prohibited, reason)
		return
	}
	stream, err := t.openStream(sconn.RemoteAddr().String())
	if err != nil {
		newCh.Reject(ssh.ConnectionFailed, "the tunnel's agent is unreachable")
		return
	}
	ch, chReqs, err := newCh.Accept()
	if err != nil {
		stream.Close()
		return
	}
	go ssh.DiscardRequests(chReqs)
	start := time.Now()
	res := pipe.Join(ch, stream)
	log.Info("gateway connection closed", "tunnel", t.endpoint.GetName(), "duration_ms", time.Since(start).Milliseconds(),
		"bytes_in", res.AtoB, "bytes_out", res.BtoA)
}

// gatewayTarget resolves and authorizes a forward. The key is looked up
// again, so removing it takes effect for new channels at once.
func (s *Server) gatewayTarget(sconn *ssh.ServerConn, req directTCPIP) (*tunnel, string) {
	host := strings.ToLower(strings.TrimSuffix(req.Host, "."))
	if !strings.Contains(host, ".") {
		host += "." + s.cfg.BaseDomain
	}
	name := s.rules.TunnelName(host)
	if name == "" {
		return nil, "unknown tunnel " + req.Host
	}
	t, typ, _ := s.registry.lookup(name)
	if t == nil || !hasPublicPort(typ) {
		return nil, "no connected ssh/tcp tunnel named " + name
	}
	if req.Port != 22 && req.Port != t.endpoint.GetPublicPort() {
		return nil, fmt.Sprintf("tunnel %s is reached on port 22", name)
	}
	key, err := s.cfg.SSHGateway.Keys.GatewayKeyByFingerprint(sconn.Permissions.Extensions["fingerprint"])
	if err != nil || key == nil {
		return nil, "the key was removed"
	}
	if !key.Allows(name, t.access.RequiresToken()) {
		return nil, "this key isn't granted tunnel " + name
	}
	if !t.access.AllowsIP(remoteIP(sconn.RemoteAddr())) {
		s.counters.rejectedIP.Add(1)
		return nil, "your address isn't allowed by tunnel " + name
	}
	return t, ""
}

func (s *Server) trackGateway(c *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gatewayConns[c] = struct{}{}
}

func (s *Server) untrackGateway(c *ssh.ServerConn) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.gatewayConns, c)
}
