// Package admin is the local management interface: an HTTP API on a Unix
// socket for the relay (tokens, reservations, status) and the agent
// (status), and the CLI commands that call it.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"time"
)

// Default socket paths (systemd RuntimeDirectory=l8tunnel / l8tunnel-agent).
const (
	DefaultServerSocket = "/run/l8tunnel/admin.sock"
	DefaultAgentSocket  = "/run/l8tunnel-agent/status.sock"
)

// maxSocketPath is the longest Unix socket path every supported OS accepts
// (sun_path is 108 bytes on Linux, 104 on macOS, including the NUL).
const maxSocketPath = 103

func checkSocketPath(path string) error {
	if len(path) > maxSocketPath {
		return fmt.Errorf("socket path %s is %d bytes; Unix sockets allow at most %d", path, len(path), maxSocketPath)
	}
	return nil
}

// ListenUnix listens on a Unix socket only the owner can use (mode 0600).
// A stale socket file left by a previous run is replaced; any other file
// at path is an error.
func ListenUnix(path string) (net.Listener, error) {
	if err := checkSocketPath(path); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return nil, fmt.Errorf("create socket directory: %w", err)
	}
	if fi, err := os.Lstat(path); err == nil {
		if fi.Mode()&fs.ModeSocket == 0 {
			return nil, fmt.Errorf("%s exists and is not a socket", path)
		}
		if conn, err := net.DialTimeout("unix", path, time.Second); err == nil {
			conn.Close()
			return nil, fmt.Errorf("%s is in use (is another instance running?)", path)
		}
		if err := os.Remove(path); err != nil {
			return nil, fmt.Errorf("remove stale socket: %w", err)
		}
	}
	ln, err := net.Listen("unix", path)
	if err != nil {
		return nil, fmt.Errorf("listen on %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return nil, fmt.Errorf("chmod %s: %w", path, err)
	}
	return ln, nil
}

// Serve serves handler on ln until ctx ends.
func Serve(ctx context.Context, ln net.Listener, handler http.Handler, logger *slog.Logger) {
	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ErrorLog:          slog.NewLogLogger(logger.Handler(), slog.LevelDebug),
	}
	go func() {
		<-ctx.Done()
		srv.Close()
	}()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		logger.Error("admin socket stopped", "error", err)
	}
}

// apiError is the JSON body of every error response.
type apiError struct {
	Error string `json:"error"`
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, apiError{Error: err.Error()})
}
