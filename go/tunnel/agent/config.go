// Package agent implements l8tunnel-agent: it connects out to the relay
// and forwards the relay's streams to local targets.
package agent

import (
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"time"

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
	// Token authenticates the agent to the relay.
	Token string
	// AgentID identifies this agent in relay logs; empty generates one.
	AgentID string
	// Version is reported to the relay.
	Version string
	Tunnels []TunnelConfig
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
	if c.Token == "" {
		return fmt.Errorf("agent: a token is required")
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
		if t.PublicPort != 0 && t.Type != l8tunnel.TunnelType_TUNNEL_TYPE_TCP && t.Type != l8tunnel.TunnelType_TUNNEL_TYPE_SSH {
			return fmt.Errorf("agent: tunnel %q: public_port applies only to tcp and ssh tunnels", t.Name)
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

// ParseTunnelType maps a CLI/config name (tcp, ssh, http, tls) to its type.
func ParseTunnelType(s string) (l8tunnel.TunnelType, error) {
	switch strings.ToLower(s) {
	case "tcp":
		return l8tunnel.TunnelType_TUNNEL_TYPE_TCP, nil
	case "ssh":
		return l8tunnel.TunnelType_TUNNEL_TYPE_SSH, nil
	case "http":
		return l8tunnel.TunnelType_TUNNEL_TYPE_HTTP, nil
	case "tls":
		return l8tunnel.TunnelType_TUNNEL_TYPE_TLS, nil
	}
	return l8tunnel.TunnelType_TUNNEL_TYPE_UNSPECIFIED, fmt.Errorf("unknown tunnel type %q (want tcp, ssh, http or tls)", s)
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
