// Package relay implements l8tunnel-server: it accepts agent sessions and
// forwards public connections to them.
package relay

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

// Config configures a relay Server.
type Config struct {
	// ControlAddr is where agents connect, for example ":443".
	ControlAddr string
	// TLS is the relay's server TLS config (see transport.ServerTLSConfig).
	TLS *tls.Config
	// Tokens are the agent tokens the relay accepts.
	Tokens *auth.Tokens
	// PublicHost is the host name reported to agents in public addresses.
	PublicHost string
	// BindHost is the address public TCP listeners bind to; empty means all
	// interfaces.
	BindHost string
	// TCPPortMin and TCPPortMax bound the public ports for TCP/SSH tunnels.
	TCPPortMin int
	TCPPortMax int
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
	if !hasALPN(c.TLS.NextProtos) {
		return fmt.Errorf("relay: TLS config must offer ALPN %q", protocol.ALPN)
	}
	if c.Tokens == nil {
		return fmt.Errorf("relay: Tokens are required")
	}
	if c.PublicHost == "" {
		return fmt.Errorf("relay: PublicHost is required")
	}
	if c.TCPPortMin < 1 || c.TCPPortMax > 65535 || c.TCPPortMin > c.TCPPortMax {
		return fmt.Errorf("relay: invalid TCP port range %d-%d", c.TCPPortMin, c.TCPPortMax)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

func hasALPN(protos []string) bool {
	for _, p := range protos {
		if p == protocol.ALPN {
			return true
		}
	}
	return false
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
