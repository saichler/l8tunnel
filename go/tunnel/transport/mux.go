package transport

import (
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/hashicorp/yamux"
)

// Session is a multiplexed agent <-> relay connection.
type Session struct {
	mux *yamux.Session
}

// Stream is one multiplexed stream. It adds CloseWrite, so streams can be
// half-closed like TCP connections.
type Stream struct {
	*yamux.Stream
}

// CloseWrite half-closes the stream: yamux's Close sends FIN and still
// allows reading until the peer closes its side.
func (s *Stream) CloseWrite() error {
	return s.Stream.Close()
}

func muxConfig(logger *slog.Logger) *yamux.Config {
	cfg := yamux.DefaultConfig()
	cfg.EnableKeepAlive = true
	cfg.KeepAliveInterval = 15 * time.Second
	cfg.ConnectionWriteTimeout = 30 * time.Second
	cfg.LogOutput = nil
	cfg.Logger = slog.NewLogLogger(logger.Handler(), slog.LevelWarn)
	return cfg
}

// NewServerSession wraps the relay side of an agent connection.
func NewServerSession(conn io.ReadWriteCloser, logger *slog.Logger) (*Session, error) {
	mux, err := yamux.Server(conn, muxConfig(logger))
	if err != nil {
		return nil, fmt.Errorf("start mux server: %w", err)
	}
	return &Session{mux: mux}, nil
}

// NewClientSession wraps the agent side of the relay connection.
func NewClientSession(conn io.ReadWriteCloser, logger *slog.Logger) (*Session, error) {
	mux, err := yamux.Client(conn, muxConfig(logger))
	if err != nil {
		return nil, fmt.Errorf("start mux client: %w", err)
	}
	return &Session{mux: mux}, nil
}

// Open opens a new stream to the peer.
func (s *Session) Open() (*Stream, error) {
	st, err := s.mux.OpenStream()
	if err != nil {
		return nil, fmt.Errorf("open stream: %w", err)
	}
	return &Stream{Stream: st}, nil
}

// Accept waits for the peer to open a stream.
func (s *Session) Accept() (*Stream, error) {
	st, err := s.mux.AcceptStream()
	if err != nil {
		return nil, err
	}
	return &Stream{Stream: st}, nil
}

// Close tears down the session and all its streams.
func (s *Session) Close() error {
	return s.mux.Close()
}

// Done is closed when the session ends.
func (s *Session) Done() <-chan struct{} {
	return s.mux.CloseChan()
}
