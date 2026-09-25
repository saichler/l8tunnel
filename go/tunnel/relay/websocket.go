package relay

import (
	"log/slog"
	"net/http"
	"time"

	"github.com/gorilla/websocket"

	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// newWebSocketServer serves agent sessions over WebSocket on the control
// SNI, for agents behind HTTP-only proxies (transport: wss). The router
// hands it connections that offered http/1.1 instead of the l8tunnel ALPN.
func (s *Server) newWebSocketServer() (*http.Server, *transport.ConnListener) {
	upgrader := websocket.Upgrader{
		HandshakeTimeout: handshakeTimeout,
		ReadBufferSize:   32 << 10,
		WriteBufferSize:  32 << 10,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+transport.WebSocketPath, func(w http.ResponseWriter, r *http.Request) {
		if !s.enter() {
			http.Error(w, "relay is shutting down", http.StatusServiceUnavailable)
			return
		}
		defer s.wg.Done()
		ws, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			return // Upgrade has written the error response
		}
		conn := transport.NewWebSocketConn(ws)
		s.serveAgent(conn, s.log.With("remote", conn.RemoteAddr().String(), "transport", "wss"))
		conn.Close()
	})
	ln := transport.NewConnListener()
	srv := &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: handshakeTimeout,
		IdleTimeout:       time.Minute,
		ErrorLog:          slog.NewLogLogger(s.log.Handler(), slog.LevelDebug),
	}
	return srv, ln
}

// enter registers a goroutine that Close must wait for; it returns false
// once the relay is closing.
func (s *Server) enter() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return false
	}
	s.wg.Add(1)
	return true
}
