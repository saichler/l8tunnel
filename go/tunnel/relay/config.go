// Package relay implements l8tunnel-server: it accepts agent sessions and
// forwards public connections to them.
package relay

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net/http"
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

	// Default per-IP rate limits.
	DefaultConnectionsPerSecond  = 20
	DefaultConnectionsBurst      = 100
	DefaultAuthFailuresPerMinute = 5
)

// TokenStore looks up agent tokens by ID; it returns nil (and no error)
// for an unknown ID. store.Store implements it.
type TokenStore interface {
	TokenByID(id string) (*auth.TokenRecord, error)
}

// PermanentReservation binds a tunnel name (and, for tcp/ssh, a public
// port) to a token until an operator removes it.
type PermanentReservation struct {
	Name    string
	TokenID string
	Port    int
}

// RateLimits are per client IP.
type RateLimits struct {
	// ConnectionsPerSecond and ConnectionsBurst limit new connections to
	// the TLS listener and tunnel ports; zero means the defaults.
	ConnectionsPerSecond float64
	ConnectionsBurst     int
	// AuthFailuresPerMinute is how many failed agent authentications an
	// IP may make before its agent connections are refused until the
	// budget refills; zero means the default.
	AuthFailuresPerMinute int
}

// Config configures a relay Server.
type Config struct {
	// ControlAddr is the shared TLS listener for agents and all SNI-routed
	// tunnel traffic, for example ":443".
	ControlAddr string
	// HTTPAddr is an optional plain HTTP listener, for example ":80", that
	// redirects to HTTPS and serves ACME HTTP-01 challenges; empty disables
	// it.
	HTTPAddr string
	// HTTPChallenge wraps the HTTP listener's redirect handler so ACME
	// HTTP-01 challenges are answered; nil means no ACME challenges.
	HTTPChallenge func(next http.Handler) http.Handler
	// PublicHTTPSPort is the port clients use to reach ControlAddr, used in
	// public URLs and redirects; zero means ControlAddr's port.
	PublicHTTPSPort int
	// DisableForwardedHeaders stops the relay adding X-Forwarded-For,
	// -Host and -Proto to HTTP tunnel requests.
	DisableForwardedHeaders bool
	// AccessLog logs every HTTP tunnel request.
	AccessLog bool
	// Version is reported in logs and metrics.
	Version string
	// TLS is the relay's server TLS config (see transport.ServerTLSConfig).
	// Its certificates must cover ControlSNI and *.BaseDomain.
	TLS *tls.Config
	// BaseDomain is the parent domain of tunnel host names: tunnel "db" is
	// reachable by SNI as db.<BaseDomain>.
	BaseDomain string
	// ControlSNI is the server name agents connect with; empty means
	// "connect." + BaseDomain.
	ControlSNI string
	// Tokens looks up the agent tokens the relay accepts.
	Tokens TokenStore
	// Reservations are loaded at start; more can be added with Reserve.
	Reservations []PermanentReservation
	// RateLimits are per client IP.
	RateLimits RateLimits
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
	if c.TLS == nil || (len(c.TLS.Certificates) == 0 && c.TLS.GetCertificate == nil) {
		return fmt.Errorf("relay: a TLS config with a certificate is required")
	}
	if c.PublicHTTPSPort < 0 || c.PublicHTTPSPort > 65535 {
		return fmt.Errorf("relay: invalid PublicHTTPSPort %d", c.PublicHTTPSPort)
	}
	if c.HTTPChallenge == nil {
		c.HTTPChallenge = func(next http.Handler) http.Handler { return next }
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
	if c.RateLimits.ConnectionsPerSecond < 0 || c.RateLimits.ConnectionsBurst < 0 || c.RateLimits.AuthFailuresPerMinute < 0 {
		return fmt.Errorf("relay: rate limits must not be negative")
	}
	if c.RateLimits.ConnectionsPerSecond == 0 {
		c.RateLimits.ConnectionsPerSecond = DefaultConnectionsPerSecond
	}
	if c.RateLimits.ConnectionsBurst == 0 {
		c.RateLimits.ConnectionsBurst = DefaultConnectionsBurst
	}
	if c.RateLimits.AuthFailuresPerMinute == 0 {
		c.RateLimits.AuthFailuresPerMinute = DefaultAuthFailuresPerMinute
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}
