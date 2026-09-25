package relay

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
)

// Server is the relay. Its shared TLS listener carries agent sessions
// (control SNI) and every tunnel's SNI traffic (<name>.<base-domain>);
// each TCP/SSH tunnel also gets a dedicated public port (mode A). An
// optional plain HTTP listener redirects to HTTPS and serves ACME
// HTTP-01 challenges.
type Server struct {
	cfg      Config
	log      *slog.Logger
	registry *registry
	routes   routeConfigs
	http     *httpproxy.Proxy

	mu         sync.Mutex
	listener   net.Listener
	httpServer *http.Server
	httpAddr   string
	httpsPort  int
	sessions   map[*agentSession]struct{}
	closed     bool
	wg         sync.WaitGroup
}

// New validates cfg and returns a relay that isn't listening yet.
func New(cfg Config) (*Server, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	s := &Server{
		cfg:      cfg,
		log:      cfg.Logger,
		registry: newRegistry(cfg.NameGracePeriod),
		routes:   newRouteConfigs(cfg.TLS),
		sessions: map[*agentSession]struct{}{},
	}
	s.http = httpproxy.New(httpproxy.Config{
		BaseDomain:       cfg.BaseDomain,
		ForwardedHeaders: !cfg.DisableForwardedHeaders,
		Lookup:           s.lookupHTTP,
		Logger:           cfg.Logger,
	})
	return s, nil
}

// Start opens the listeners and begins accepting connections.
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
	s.httpsPort = s.cfg.PublicHTTPSPort
	if s.httpsPort == 0 {
		s.httpsPort = ln.Addr().(*net.TCPAddr).Port
	}

	if s.cfg.HTTPAddr != "" {
		httpLn, err := net.Listen("tcp", s.cfg.HTTPAddr)
		if err != nil {
			ln.Close()
			return fmt.Errorf("relay: listen on %s: %w", s.cfg.HTTPAddr, err)
		}
		s.httpAddr = httpLn.Addr().String()
		s.httpServer = &http.Server{
			Handler:           s.cfg.HTTPChallenge(httpproxy.RedirectHandler(s.httpsPort)),
			ReadHeaderTimeout: 10 * time.Second,
			ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			// Serve returns http.ErrServerClosed after Close.
			s.httpServer.Serve(httpLn)
		}()
	}

	s.listener = ln
	s.log.Info("relay listening", "tls", ln.Addr().String(), "http", s.httpAddr,
		"control_sni", s.cfg.ControlSNI, "base_domain", s.cfg.BaseDomain,
		"public_https_port", s.httpsPort, "tcp_ports", fmt.Sprintf("%d-%d", s.cfg.TCPPortMin, s.cfg.TCPPortMax))
	s.wg.Add(1)
	go s.acceptConns(ln)
	return nil
}

// Addr returns the TLS listener's address, or nil before Start.
func (s *Server) Addr() net.Addr {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.listener == nil {
		return nil
	}
	return s.listener.Addr()
}

// HTTPAddr returns the plain HTTP listener's address, or "" when it is
// disabled or before Start.
func (s *Server) HTTPAddr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpAddr
}

func (s *Server) publicHTTPSPort() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.httpsPort
}

// Close stops accepting connections, ends every session (which closes
// their tunnels), waits for all goroutines to finish and releases every
// reservation.
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
	if s.httpServer != nil {
		s.httpServer.Close()
	}
	for sess := range s.sessions {
		sess.mux.Close()
	}
	s.mu.Unlock()
	s.http.Close()
	s.wg.Wait()
	s.registry.close()
	return err
}

func (s *Server) acceptConns(ln net.Listener) {
	defer s.wg.Done()
	for {
		conn, err := ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			s.log.Warn("accept connection failed", "error", err)
			time.Sleep(100 * time.Millisecond)
			continue
		}
		s.wg.Add(1)
		go func() {
			defer s.wg.Done()
			s.serveConn(conn.(*net.TCPConn))
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
