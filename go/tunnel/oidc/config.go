// Package oidc protects HTTP tunnels with an OpenID Connect login at a
// provider the relay operator configured. One auth host
// (auth.<base-domain>) handles the provider round trip for every tunnel,
// because providers don't accept wildcard redirect URIs; each tunnel host
// then keeps its own signed session cookie.
package oidc

import (
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"sort"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

// DefaultSessionTTL is how long a login lasts on a tunnel host.
const DefaultSessionTTL = 12 * time.Hour

// ProviderConfig is one OIDC provider.
type ProviderConfig struct {
	Issuer       string
	ClientID     string
	ClientSecret string
	// Scopes default to openid, email, profile.
	Scopes []string
}

// Config configures a Service.
type Config struct {
	// AuthHost is the relay's login host, e.g. auth.tunnel.example.com.
	AuthHost  string
	Providers map[string]ProviderConfig
	// SessionTTL defaults to DefaultSessionTTL.
	SessionTTL time.Duration
	// Key signs states, codes and cookies (at least 32 bytes).
	Key []byte
	// ErrorPage writes the relay's HTML error page.
	ErrorPage func(w http.ResponseWriter, status int, code, title, message, host string)
	// HTTPClient talks to the providers; nil means a default client.
	HTTPClient *http.Client
	Logger     *slog.Logger
}

func (c *Config) validate() error {
	if c.AuthHost == "" {
		return fmt.Errorf("oidc: auth host is required")
	}
	if len(c.Providers) == 0 {
		return fmt.Errorf("oidc.providers: at least one provider is required")
	}
	for name, p := range c.Providers {
		u, err := url.Parse(p.Issuer)
		if err != nil || u.Host == "" {
			return fmt.Errorf("oidc.providers.%s.issuer %q is not a URL", name, p.Issuer)
		}
		// Plain http only for a provider on this machine (development).
		if u.Scheme != "https" && !(u.Scheme == "http" && isLoopback(u.Hostname())) {
			return fmt.Errorf("oidc.providers.%s.issuer must be https", name)
		}
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("oidc.providers.%s: client_id and client_secret are required", name)
		}
	}
	if len(c.Key) < 32 {
		return fmt.Errorf("oidc: signing key must be at least 32 bytes")
	}
	if c.SessionTTL < 0 {
		return fmt.Errorf("oidc.session_ttl must not be negative")
	}
	if c.SessionTTL == 0 {
		c.SessionTTL = DefaultSessionTTL
	}
	if c.ErrorPage == nil {
		return fmt.Errorf("oidc: ErrorPage is required")
	}
	if c.HTTPClient == nil {
		c.HTTPClient = &http.Client{Timeout: 15 * time.Second}
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

func isLoopback(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// Binding connects the service to the relay once the relay exists.
type Binding struct {
	// RuleFor returns the OIDC rule of the active tunnel serving host, or
	// nil. The auth host only redirects back to such hosts.
	RuleFor func(host string) *auth.OIDCRule
	// HTTPSPort is the public HTTPS port (443 is left out of URLs).
	HTTPSPort func() int
}

// ProviderNames lists the configured providers.
func (s *Service) ProviderNames() []string {
	names := make([]string, 0, len(s.cfg.Providers))
	for n := range s.cfg.Providers {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}
