//go:build !darwin

package admin

// Default socket paths (systemd RuntimeDirectory=l8tunnel / l8tunnel-agent).
const (
	DefaultServerSocket = "/run/l8tunnel/admin.sock"
	DefaultAgentSocket  = "/run/l8tunnel-agent/status.sock"
)
