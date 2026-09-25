package relay

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"
)

// Server is the relay: it accepts agent sessions on the control address
// and serves their tunnels' public listeners.
type Server struct {
	cfg      Config
	log      *slog.Logger
	registry *registry

	mu       sync.Mutex
	listener net.Listener
	sessions map[*agentSession]struct{}
	closed   bool
	wg       sync.WaitGroup
}

// New validates cfg and returns a relay that isn't listening yet.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		registry: newRegistry(),
		sessions: map[*agentSession]struct{}{},
	}, nil
}

// Start opens the control listener and begins accepting agents.
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return fmt.Errorf("relay: server is closed")
	}
	if s.listener != nil {
		return fmt.Errorf("relay: server already started")
	}
	ln, err := net.Listen("tcp", s.cfg.ControlAddr)
	if err != nil {
		return fmt.Errorf("relay: listen on %s: %w", s.cfg.ControlAddr, err)
	}
	s.listener = tls.NewListener(ln, s.cfg.TLS)
	s.log.Info("relay listening", "control", ln.Addr().String(),
		"tcp_ports", fmt.Sprintf("%d-%d", s.cfg.TCPPortMin, s.cfg.TCPPortMax))
	s.wg.Add(1)
	go s.acceptAgents(s.listener)
	return nil
}

// Addr returns the control listener's address, or nil before Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// Close stops accepting agents, ends every session (which closes their
// tunnels) and waits for all goroutines to finish.
func (s *Server) Close() error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil
	}
	s.closed = true
	var err error
	if s.listener != nil {
		err = s.listener.Close()
	}
	for sess := range s.sessions {
		sess.mux.Close()
	}
	s.mu.Unlock()
	s.wg.Wait()
	return err
}

func (s *Server) acceptAgents(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept agent connection failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveAgent(conn.(*tls.Conn))
		}()
	}
}

// track adds a session; it returns false when the server is closing.
func (s *Server) track(sess *agentSession) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.sessions[sess] = struct{}{}
	return true
}

func (s *Server) untrack(sess *agentSession) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, sess)
}

// goTracked runs fn in a goroutine that Close waits for.
func (s *Server) goTracked(fn func()) {
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		fn()
	}()
}
