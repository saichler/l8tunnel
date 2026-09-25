// Package agent implements l8tunnel-agent: it connects out to the relay
// and forwards the relay's streams to local targets.
package agent

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

const (
	// DefaultSSHTarget is used for SSH tunnels without an explicit target.
	DefaultSSHTarget = "127.0.0.1:22"
	// DefaultReconnectMin and DefaultReconnectMax bound the exponential
	// backoff between reconnect attempts.
	DefaultReconnectMin = time.Second
	DefaultReconnectMax = time.Minute
)

// TunnelConfig is one tunnel the agent exposes.
type TunnelConfig struct {
	// Name is the requested public name; empty lets the relay pick one.
	Name string
	Type l8tunnel.TunnelType
	// Target is the local host:port the agent dials for each connection.
	Target string
	// TargetTLS makes the agent speak TLS to Target (HTTP tunnels whose
	// local service is HTTPS).
	TargetTLS bool
	// InsecureSkipVerify skips verifying Target's certificate, for local
	// services with self-signed certificates. Requires TargetTLS.
	InsecureSkipVerify bool
	// PublicPort requests a fixed relay port (TCP/SSH only); 0 lets the
	// relay allocate one.
	PublicPort uint32
	// AllowIPs and DenyIPs (addresses or CIDRs) restrict which clients the
	// relay lets through; deny wins, and an empty allow list means all.
	AllowIPs, DenyIPs []string
	// BasicUsers require HTTP basic auth at the relay (HTTP tunnels only).
	BasicUsers []BasicUser
	// OIDC requires a login at one of the relay's OIDC providers (HTTP
	// tunnels only); nil means none.
	OIDC *OIDCConfig
	// Domains are custom domains (CNAME to the relay) this tunnel also
	// serves; HTTP/TLS only, and the token's policy must allow them.
	Domains []string
	// AccessToken requires mode B clients to present this token
	// ("l8tunnel connect --access-token"); TCP/SSH only, and the tunnel
	// then has no mode A port. Only its SHA-256 is sent to the relay.
	AccessToken string
}

// OIDCConfig is a tunnel's OIDC login requirement.
type OIDCConfig struct {
	Provider     string
	AllowEmails  []string
	AllowDomains []string
}

// BasicUser is an HTTP basic-auth user with a bcrypt password hash.
type BasicUser struct {
	Username   string
	BcryptHash string
}

// accessPolicy is the tunnel's access policy as sent to the relay.
func (t TunnelConfig) accessPolicy() *l8tunnel.AccessPolicy {
	p := &l8tunnel.AccessPolicy{AllowIps: t.AllowIPs, DenyIps: t.DenyIPs}
	for _, u := range t.BasicUsers {
		p.BasicUsers = append(p.BasicUsers, &l8tunnel.BasicUser{Username: u.Username, BcryptHash: u.BcryptHash})
	}
	if t.AccessToken != "" {
		p.AccessTokenSha256 = auth.HashAccessToken(t.AccessToken)
	}
	if t.OIDC != nil {
		p.Oidc = &l8tunnel.OIDCPolicy{Provider: t.OIDC.Provider, AllowEmails: t.OIDC.AllowEmails, AllowDomains: t.OIDC.AllowDomains}
	}
	return p
}

// targetString is the target as shown in logs.
func (t TunnelConfig) targetString() string {
	if t.TargetTLS {
		return "https://" + t.Target
	}
	return t.Target
}

// Config configures an Agent.
type Config struct {
	// RelayAddr is the relay's control address, host:port.
	RelayAddr string
	// TLS is the agent's client TLS config (see transport.ClientTLSConfig).
	TLS *tls.Config
	// Token authenticates the agent to the relay. It may be empty when TLS
	// carries a client certificate issued by the relay.
	Token string
	// AgentID identifies this agent in relay logs; empty generates one.
	AgentID string
	// Version is reported to the relay.
	Version string
	Tunnels []TunnelConfig
	// Transport is transport.TransportTLS (default when empty) or
	// transport.TransportWebSocket for networks that only allow HTTP(S).
	Transport string
	// Proxy is an http:// proxy URL, transport.ProxyNone, or empty to use
	// HTTPS_PROXY / NO_PROXY from the environment.
	Proxy string
	// ReconnectMin and ReconnectMax bound the reconnect backoff; zero
	// means DefaultReconnectMin / DefaultReconnectMax.
	ReconnectMin time.Duration
	ReconnectMax time.Duration
	// Logger receives the agent's logs; nil means slog.Default().
	Logger *slog.Logger
}

func (c *Config) validate() error {
	if _, _, err := net.SplitHostPort(c.RelayAddr); err != nil {
		return fmt.Errorf("agent: relay address %q must be host:port: %w", c.RelayAddr, err)
	}
	if c.TLS == nil || c.TLS.ServerName == "" {
		return fmt.Errorf("agent: a TLS config with a server name is required")
	}
	if c.Token == "" && len(c.TLS.Certificates) == 0 {
		return fmt.Errorf("agent: a token or a client certificate is required")
	}
	switch c.Transport {
	case "":
		c.Transport = transport.TransportTLS
	case transport.TransportTLS, transport.TransportWebSocket:
	default:
		return fmt.Errorf("agent: transport %q must be %s or %s", c.Transport, transport.TransportTLS, transport.TransportWebSocket)
	}
	if err := transport.ParseProxy(c.Proxy); err != nil {
		return fmt.Errorf("agent: %w", err)
	}
	if len(c.Tunnels) == 0 {
		return fmt.Errorf("agent: at least one tunnel is required")
	}
	names := map[string]bool{}
	for i := range c.Tunnels {
		t := &c.Tunnels[i]
		switch t.Type {
		case l8tunnel.TunnelType_TUNNEL_TYPE_TCP, l8tunnel.TunnelType_TUNNEL_TYPE_HTTP, l8tunnel.TunnelType_TUNNEL_TYPE_TLS:
		case l8tunnel.TunnelType_TUNNEL_TYPE_SSH:
			if t.Target == "" {
				t.Target = DefaultSSHTarget
			}
		default:
			return fmt.Errorf("agent: tunnel %q: invalid type %s", t.Name, t.Type)
		}
		if t.TargetTLS && t.Type != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
			return fmt.Errorf("agent: tunnel %q: an https target applies only to http tunnels", t.Name)
		}
		if t.InsecureSkipVerify && !t.TargetTLS {
			return fmt.Errorf("agent: tunnel %q: insecure_skip_verify requires an https target", t.Name)
		}
		if _, err := auth.ValidateSpecAccess(t.Type, t.PublicPort, t.accessPolicy()); err != nil {
			return fmt.Errorf("agent: tunnel %q: %w", t.Name, err)
		}
		if len(t.Domains) > 0 && t.Type != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP && t.Type != l8tunnel.TunnelType_TUNNEL_TYPE_TLS {
			return fmt.Errorf("agent: tunnel %q: custom domains apply only to http and tls tunnels", t.Name)
		}
		for _, d := range t.Domains {
			if _, err := protocol.NormalizeDomain(d); err != nil {
				return fmt.Errorf("agent: tunnel %q: %w", t.Name, err)
			}
		}
		if _, _, err := net.SplitHostPort(t.Target); err != nil {
			return fmt.Errorf("agent: tunnel %q: target %q must be host:port", t.Name, t.Target)
		}
		if t.Name != "" {
			if names[t.Name] {
				return fmt.Errorf("agent: duplicate tunnel name %q", t.Name)
			}
			names[t.Name] = true
		}
	}
	if c.ReconnectMin == 0 {
		c.ReconnectMin = DefaultReconnectMin
	}
	if c.ReconnectMax == 0 {
		c.ReconnectMax = DefaultReconnectMax
	}
	if c.ReconnectMin < 0 || c.ReconnectMin > c.ReconnectMax {
		return fmt.Errorf("agent: invalid reconnect backoff %s-%s", c.ReconnectMin, c.ReconnectMax)
	}
	if c.Logger == nil {
		c.Logger = slog.Default()
	}
	return nil
}

// ServerName returns the host part of a host:port relay address, used as
// the TLS server name when none is given.
func ServerName(relayAddr string) (string, error) {
	host, _, err := net.SplitHostPort(relayAddr)
	if err != nil {
		return "", fmt.Errorf("relay address %q must be host:port: %w", relayAddr, err)
	}
	return host, nil
}
