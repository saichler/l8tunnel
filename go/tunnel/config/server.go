package config

import (
	"fmt"
	"log/slog"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

const (
	defaultListen       = ":443"
	defaultTCPPortRange = "22000-22999"
)

// ServerFile is the relay configuration from server.yaml.
type ServerFile struct {
	// BaseDomain: tunnels are reachable as <name>.<base_domain>.
	BaseDomain string `yaml:"base_domain"`
	// ControlSNI is the host agents connect to; empty means
	// connect.<base_domain>.
	ControlSNI string `yaml:"control_sni"`
	// PublicHost is used in mode A addresses; empty means base_domain.
	PublicHost string `yaml:"public_host"`
	Listen     struct {
		// HTTPS is the shared TLS listener; empty means ":443".
		HTTPS string `yaml:"https"`
	} `yaml:"listen"`
	// Bind is the address public tunnel ports bind to; empty means all.
	Bind string `yaml:"bind"`
	// TCPPortRange is "min-max"; empty means 22000-22999.
	TCPPortRange string `yaml:"tcp_port_range"`
	TLS          struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	// TokensFile has one "<name> <token>" pair per line.
	TokensFile string `yaml:"tokens_file"`
	// HeartbeatInterval and NameGracePeriod are durations such as "15s";
	// empty means the relay defaults (15s and 5m).
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	NameGracePeriod   time.Duration `yaml:"name_grace_period"`
}

// LoadServerFile reads a server YAML file.
func LoadServerFile(path string) (*ServerFile, error) {
	f := &ServerFile{}
	if err := decodeStrict(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// RelayConfig builds the relay configuration. relay.New validates the
// result further.
func (f *ServerFile) RelayConfig(logger *slog.Logger) (relay.Config, error) {
	tlsCfg, err := transport.ServerTLSConfig(f.TLS.Cert, f.TLS.Key)
	if err != nil {
		return relay.Config{}, fmt.Errorf("tls: %w", err)
	}
	tokens, err := auth.LoadTokensFile(f.TokensFile)
	if err != nil {
		return relay.Config{}, fmt.Errorf("tokens_file: %w", err)
	}
	portRange := f.TCPPortRange
	if portRange == "" {
		portRange = defaultTCPPortRange
	}
	portMin, portMax, err := relay.ParsePortRange(portRange)
	if err != nil {
		return relay.Config{}, fmt.Errorf("tcp_port_range: %w", err)
	}
	listen := f.Listen.HTTPS
	if listen == "" {
		listen = defaultListen
	}
	return relay.Config{
		ControlAddr:       listen,
		TLS:               tlsCfg,
		BaseDomain:        f.BaseDomain,
		ControlSNI:        f.ControlSNI,
		Tokens:            tokens,
		PublicHost:        f.PublicHost,
		BindHost:          f.Bind,
		TCPPortMin:        portMin,
		TCPPortMax:        portMax,
		HeartbeatInterval: f.HeartbeatInterval,
		NameGracePeriod:   f.NameGracePeriod,
		Logger:            logger,
	}, nil
}
