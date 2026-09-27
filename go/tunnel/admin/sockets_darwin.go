package admin

// Default socket paths on macOS, which has no /run (the directory is
// created when the socket is).
const (
	DefaultServerSocket = "/var/run/l8tunnel/admin.sock"
	DefaultAgentSocket  = "/var/run/l8tunnel-agent/status.sock"
)
