package config

import (
	"fmt"
	"net/netip"
	"os"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/registry"
)

// ClusterEnv names the cluster configuration file for the Kubernetes
// processes (backend, registry, relays, edge).
const ClusterEnv = "L8TUNNEL_CLUSTER_CONFIG"

// DefaultClusterConfig is where the cluster ConfigMap is mounted.
const DefaultClusterConfig = "/etc/l8tunnel/cluster.yaml"

// DefaultClusterSecretDir is where the l8tunnel-cluster Secret is mounted.
const DefaultClusterSecretDir = "/etc/l8tunnel/cluster-secret"

// Relay ports inside the cluster (pod network, unprivileged).
const (
	DefaultRelayTLSPort    = 8443
	DefaultRelayHTTPPort   = 8080
	DefaultRelayStreamPort = 8444
	DefaultRelayOpsPort    = 9100
)

// ClusterFile is cluster.yaml: the settings every l8tunnel process on
// Kubernetes shares.
type ClusterFile struct {
	// BaseDomain: tunnels are reachable as <name>.<base_domain>.
	BaseDomain string `yaml:"base_domain"`
	// ControlSNI is the host agents connect to; empty means
	// connect.<base_domain>.
	ControlSNI string `yaml:"control_sni"`
	// AuthHost is the OIDC login host; empty when OIDC is off.
	AuthHost string `yaml:"auth_host"`
	// ReservedNames can't be tunnel names.
	ReservedNames []string `yaml:"reserved_names"`
	// TCPPortRange is the public mode A range; empty means 22000-22999.
	TCPPortRange string `yaml:"tcp_port_range"`
	// Public are the ports the router forwards to the edge for tunnels.
	Public struct {
		HTTPS int `yaml:"https"` // default 443
		HTTP  int `yaml:"http"`  // default 80; -1 disables
		// Gateway is the SSH gateway's public port; 0 disables it.
		Gateway int `yaml:"gateway"`
	} `yaml:"public"`
	// Relay are the relays' ports inside the cluster.
	Relay struct {
		TLS     int `yaml:"tls"`     // default 8443
		HTTP    int `yaml:"http"`    // default 8080
		Stream  int `yaml:"stream"`  // default 8444
		Gateway int `yaml:"gateway"` // default 2222
		Ops     int `yaml:"ops"`     // default 9100
	} `yaml:"relay"`
	// TrustedProxies are the networks whose PROXY headers relays believe:
	// the edge's node and the pod network.
	TrustedProxies []string `yaml:"trusted_proxies"`
	// SecretDir holds the l8tunnel-cluster Secret: forward-key (signs the
	// PROXY headers between the edge and relays) and gateway-host-key (the
	// SSH gateway's host key, the same on every relay). Default
	// /etc/l8tunnel/cluster-secret.
	SecretDir string `yaml:"secret_dir"`
	// AgentCA are the files of the agent CA (the l8tunnel-agent-ca Secret).
	AgentCA struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"agent_ca"`
}

// LoadClusterFile reads cluster.yaml from path, or from $L8TUNNEL_CLUSTER_CONFIG
// (or the default path) when path is empty, and fills in the defaults.
func LoadClusterFile(path string) (*ClusterFile, error) {
	if path == "" {
		path = os.Getenv(ClusterEnv)
	}
	if path == "" {
		path = DefaultClusterConfig
	}
	f := &ClusterFile{}
	if err := decodeStrict(path, f); err != nil {
		return nil, err
	}
	if err := f.normalize(); err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return f, nil
}

func (f *ClusterFile) normalize() error {
	f.BaseDomain = strings.ToLower(strings.TrimSuffix(f.BaseDomain, "."))
	if _, err := protocol.NormalizeDomain(f.BaseDomain); err != nil {
		return fmt.Errorf("base_domain: %w", err)
	}
	if f.ControlSNI == "" {
		f.ControlSNI = "connect." + f.BaseDomain
	}
	f.ControlSNI = strings.ToLower(f.ControlSNI)
	f.AuthHost = strings.ToLower(f.AuthHost)
	for _, n := range f.ReservedNames {
		if !registry.ValidName(n) {
			return fmt.Errorf("reserved_names: %q must be a lowercase DNS label", n)
		}
	}
	if f.TCPPortRange == "" {
		f.TCPPortRange = defaultTCPPortRange
	}
	if _, _, err := protocol.ParsePortRange(f.TCPPortRange); err != nil {
		return fmt.Errorf("tcp_port_range: %w", err)
	}
	if f.SecretDir == "" {
		f.SecretDir = DefaultClusterSecretDir
	}
	if _, err := auth.ParsePrefixes(f.TrustedProxies); err != nil {
		return fmt.Errorf("trusted_proxies: %w", err)
	}
	setDefault(&f.Public.HTTPS, 443)
	setDefault(&f.Public.HTTP, 80)
	setDefault(&f.Relay.TLS, DefaultRelayTLSPort)
	setDefault(&f.Relay.HTTP, DefaultRelayHTTPPort)
	setDefault(&f.Relay.Stream, DefaultRelayStreamPort)
	setDefault(&f.Relay.Gateway, 2222)
	setDefault(&f.Relay.Ops, DefaultRelayOpsPort)
	for name, p := range map[string]int{"public.https": f.Public.HTTPS, "relay.tls": f.Relay.TLS, "relay.http": f.Relay.HTTP,
		"relay.stream": f.Relay.Stream, "relay.gateway": f.Relay.Gateway, "relay.ops": f.Relay.Ops} {
		if p < 1 || p > 65535 {
			return fmt.Errorf("%s: invalid port %d", name, p)
		}
	}
	if f.Public.HTTP != -1 && (f.Public.HTTP < 1 || f.Public.HTTP > 65535) {
		return fmt.Errorf("public.http: invalid port %d (-1 disables it)", f.Public.HTTP)
	}
	if f.Public.Gateway < 0 || f.Public.Gateway > 65535 {
		return fmt.Errorf("public.gateway: invalid port %d", f.Public.Gateway)
	}
	return nil
}

func setDefault(p *int, v int) {
	if *p == 0 {
		*p = v
	}
}

// Rules are the tunnel name and port rules of the cluster.
func (f *ClusterFile) Rules() registry.Rules {
	lo, hi, _ := protocol.ParsePortRange(f.TCPPortRange) // checked by normalize
	return registry.Rules{
		BaseDomain:    f.BaseDomain,
		ControlSNI:    f.ControlSNI,
		AuthHost:      f.AuthHost,
		ReservedNames: f.ReservedNames,
		PortMin:       lo,
		PortMax:       hi,
	}
}

// TrustedPrefixes are TrustedProxies parsed (checked when loaded).
func (f *ClusterFile) TrustedPrefixes() []netip.Prefix {
	p, _ := auth.ParsePrefixes(f.TrustedProxies)
	return p
}
