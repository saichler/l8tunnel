package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// AgentFile is the agent configuration, from agent.yaml or the command
// line.
type AgentFile struct {
	// Relay is the relay's control address, host:port. The host should be
	// the relay's control SNI, e.g. connect.tunnel.example.com.
	Relay string `yaml:"relay"`
	// ServerName overrides the TLS server name; empty means Relay's host.
	ServerName string `yaml:"server_name"`
	// CA is a CA file to trust for the relay; empty means system roots.
	CA string `yaml:"ca"`
	// Token may be written as ${ENV_VAR}; empty means $L8TUNNEL_TOKEN.
	Token string `yaml:"token"`
	// Cert and Key are a client certificate issued by the relay
	// ("l8tunnel-server agent-cert issue"); with them, token is optional.
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
	// StatusSocket serves "l8tunnel-agent status"; empty disables it.
	StatusSocket string `yaml:"status_socket"`
	// Transport is tls (default) or wss (WebSocket, for HTTP-only
	// networks).
	Transport string `yaml:"transport"`
	// Proxy is an http:// proxy URL, "none", or empty for HTTPS_PROXY /
	// NO_PROXY from the environment.
	Proxy   string       `yaml:"proxy"`
	Log     LogFile      `yaml:"log"`
	Tunnels []TunnelFile `yaml:"tunnels"`
}

// TunnelFile is one tunnel in AgentFile.
type TunnelFile struct {
	Name string `yaml:"name"`
	Type string `yaml:"type"`
	// Target is a port, host:port, or for http tunnels http(s)://host:port.
	Target             string `yaml:"target"`
	PublicPort         uint32 `yaml:"public_port"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// AllowIPs and DenyIPs are addresses or CIDRs; deny wins.
	AllowIPs []string `yaml:"allow_ips"`
	DenyIPs  []string `yaml:"deny_ips"`
	// BasicAuth users (http tunnels); hashes from "l8tunnel hash-password".
	BasicAuth []BasicAuthUser `yaml:"basic_auth"`
	// AccessToken (tcp/ssh) may be written as ${ENV_VAR}.
	AccessToken string `yaml:"access_token"`
}

// BasicAuthUser is one basic_auth entry.
type BasicAuthUser struct {
	User         string `yaml:"user"`
	PasswordHash string `yaml:"password_hash"`
}

// LoadAgentFile reads an agent YAML file.
func LoadAgentFile(path string) (*AgentFile, error) {
	f := &AgentFile{}
	if err := decodeStrict(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// AgentConfig builds the agent configuration. agent.New validates the
// result further.
func (f *AgentFile) AgentConfig(logger *slog.Logger, version string) (agent.Config, error) {
	token, err := expandEnv("token", f.Token)
	if err != nil {
		return agent.Config{}, err
	}
	if token == "" {
		token = os.Getenv(TokenEnv)
	}
	serverName := f.ServerName
	if serverName == "" {
		if serverName, err = agent.ServerName(f.Relay); err != nil {
			return agent.Config{}, err
		}
	}
	tlsCfg, err := transport.ClientTLSConfig(serverName, f.CA)
	if err != nil {
		return agent.Config{}, err
	}
	if f.Cert != "" || f.Key != "" {
		if err := transport.LoadClientCert(tlsCfg, f.Cert, f.Key); err != nil {
			return agent.Config{}, err
		}
	}
	tunnels := make([]agent.TunnelConfig, 0, len(f.Tunnels))
	for _, t := range f.Tunnels {
		typ, err := protocol.ParseTunnelType(t.Type)
		if err != nil {
			return agent.Config{}, fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
		target, useTLS, err := parseTarget(t.Target)
		if err != nil {
			return agent.Config{}, fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
		if strings.Contains(t.Target, "://") && typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
			return agent.Config{}, fmt.Errorf("tunnel %q: a scheme in the target applies only to http tunnels", t.Name)
		}
		accessToken, err := expandEnv("tunnel "+t.Name+" access_token", t.AccessToken)
		if err != nil {
			return agent.Config{}, err
		}
		var users []agent.BasicUser
		for _, u := range t.BasicAuth {
			users = append(users, agent.BasicUser{Username: u.User, BcryptHash: u.PasswordHash})
		}
		tunnels = append(tunnels, agent.TunnelConfig{
			Name:               t.Name,
			Type:               typ,
			Target:             target,
			TargetTLS:          useTLS,
			InsecureSkipVerify: t.InsecureSkipVerify,
			PublicPort:         t.PublicPort,
			AllowIPs:           t.AllowIPs,
			DenyIPs:            t.DenyIPs,
			BasicUsers:         users,
			AccessToken:        accessToken,
		})
	}
	return agent.Config{
		RelayAddr: f.Relay,
		TLS:       tlsCfg,
		Token:     token,
		Version:   version,
		Transport: f.Transport,
		Proxy:     f.Proxy,
		Tunnels:   tunnels,
		Logger:    logger,
	}, nil
}
