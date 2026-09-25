// Package relay implements l8tunnel-server: it accepts agent sessions and
// forwards public connections to them.
package relay

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

const (
	// DefaultHeartbeatInterval is how often agents send Ping.
	DefaultHeartbeatInterval = 15 * time.Second
	// DefaultNameGracePeriod is how long a disconnected agent's tunnel
	// names and ports stay reserved for its token.
	DefaultNameGracePeriod = 5 * time.Minute
	// missedHeartbeats is how many intervals may pass without a Ping before
	// the relay drops the session.
	missedHeartbeats = 3
)

// Config configures a relay Server.
type Config struct {
	// ControlAddr is the TLS listener for agents and SNI-routed (mode B)
	// tunnel traffic, for example ":443".
	ControlAddr string
	// TLS is the relay's server TLS config (see transport.ServerTLSConfig).
	// Its certificate must cover ControlSNI and *.BaseDomain.
	TLS *tls.Config
	// BaseDomain is the parent domain of tunnel host names: tunnel "db" is
	// reachable by SNI as db.<BaseDomain>.
	BaseDomain string
	// ControlSNI is the server name agents connect with; empty means
	// "connect." + BaseDomain.
	ControlSNI string
	// Tokens are the agent tokens the relay accepts.
	Tokens *auth.Tokens
	// PublicHost is the host name reported in mode A public addresses;
	// empty means BaseDomain.
	PublicHost string
	// BindHost is the address public TCP listeners bind to; empty means all
	// interfaces.
	BindHost string
	// TCPPortMin and TCPPortMax bound the public ports for TCP/SSH tunnels.
	TCPPortMin int
	TCPPortMax int
	// HeartbeatInterval is sent to agents; zero means
	// DefaultHeartbeatInterval.
	HeartbeatInterval time.Duration
	// NameGracePeriod keeps a disconnected agent's names and ports
	// reserved for its token; zero means DefaultNameGracePeriod.
	NameGracePeriod time.Duration
	// Logger receives the relay's logs; nil means slog.Default().
	Logger *slog.Logger
}

func (c *Config) validate() error {
	if c.ControlAddr == "" {
		return fmt.Errorf("relay: ControlAddr is required")
	}
	if c.TLS == nil || len(c.TLS.Certificates) == 0 {
		return fmt.Errorf("relay: a TLS config with a certificate is required")
	}
	if c.Tokens == nil {
		return fmt.Errorf("relay: Tokens are required")
	}
	c.BaseDomain = strings.ToLower(strings.TrimSuffix(c.BaseDomain, "."))
	if c.BaseDomain == "" || !strings.Contains(c.BaseDomain, ".") {
		return fmt.Errorf("relay: BaseDomain %q must be a domain such as tunnel.example.com", c.BaseDomain)
	}
	if c.ControlSNI == "" {
		c.ControlSNI = "connect." + c.BaseDomain
	}
	c.ControlSNI = strings.ToLower(c.ControlSNI)
	if c.PublicHost == "" {
		c.PublicHost = c.BaseDomain
	}
	if c.HeartbeatInterval < 0 || c.NameGracePeriod < 0 {
		return fmt.Errorf("relay: HeartbeatInterval and NameGracePeriod must not be negative")
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = DefaultHeartbeatInterval
	}
	if c.NameGracePeriod == 0 {
		c.NameGracePeriod = DefaultNameGracePeriod
	}
	if c.TCPPortMin < 1 || c.TCPPortMax > 65535 || c.TCPPortMin > c.TCPPortMax {
		return fmt.Errorf("relay: invalid TCP port range %d-%d", c.TCPPortMin, c.TCPPortMax)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// ParsePortRange parses "min-max" (or a single port) into its bounds.
func ParsePortRange(s string) (int, int, error) {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	first, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	last, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if first < 1 || last > 65535 || first > last {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return first, last, nil
}
