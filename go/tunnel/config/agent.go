package config

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
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
	Token   string       `yaml:"token"`
	Tunnels []TunnelFile `yaml:"tunnels"`
}

// TunnelFile is one tunnel in AgentFile.
type TunnelFile struct {
	Name       string `yaml:"name"`
	Type       string `yaml:"type"`
	Target     string `yaml:"target"`
	PublicPort uint32 `yaml:"public_port"`
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
	tunnels := make([]agent.TunnelConfig, 0, len(f.Tunnels))
	for _, t := range f.Tunnels {
		typ, err := agent.ParseTunnelType(t.Type)
		if err != nil {
			return agent.Config{}, fmt.Errorf("tunnel %q: %w", t.Name, err)
		}
		tunnels = append(tunnels, agent.TunnelConfig{Name: t.Name, Type: typ, Target: t.Target, PublicPort: t.PublicPort})
	}
	return agent.Config{
		RelayAddr: f.Relay,
		TLS:       tlsCfg,
		Token:     token,
		Version:   version,
		Tunnels:   tunnels,
		Logger:    logger,
	}, nil
}
