package config

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
)

const (
	defaultListen       = ":443"
	defaultHTTPListen   = ":80"
	defaultTCPPortRange = "22000-22999"
	// listenOff disables the plain HTTP listener.
	listenOff = "off"
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
		// HTTP redirects to HTTPS (and answers ACME HTTP-01); empty means
		// ":80", "off" disables it.
		HTTP string `yaml:"http"`
	} `yaml:"listen"`
	// PublicHTTPSPort is the HTTPS port clients use when it differs from
	// listen.https (port forwarding); empty means listen.https's port.
	PublicHTTPSPort int `yaml:"public_https_port"`
	// ForwardedHeaders adds X-Forwarded-For/-Host/-Proto to HTTP tunnel
	// requests; empty means true.
	ForwardedHeaders *bool `yaml:"forwarded_headers"`
	// Bind is the address public tunnel ports bind to; empty means all.
	Bind string `yaml:"bind"`
	// TCPPortRange is "min-max"; empty means 22000-22999.
	TCPPortRange string `yaml:"tcp_port_range"`
	// TLS is a static certificate. Exactly one of tls and acme is set.
	TLS *struct {
		Cert string `yaml:"cert"`
		Key  string `yaml:"key"`
	} `yaml:"tls"`
	// ACME obtains certificates from an ACME CA such as Let's Encrypt.
	ACME *ACMEFile `yaml:"acme"`
	// TokensFile has one "<name> <token>" pair per line.
	TokensFile string `yaml:"tokens_file"`
	// HeartbeatInterval and NameGracePeriod are durations such as "15s";
	// empty means the relay defaults (15s and 5m).
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	NameGracePeriod   time.Duration `yaml:"name_grace_period"`
}

// ACMEFile is the acme block of server.yaml.
type ACMEFile struct {
	// Mode is dns01 (wildcard certificate through a DNS provider) or
	// http01 (per-host certificates through port 80).
	Mode  string `yaml:"mode"`
	Email string `yaml:"email"`
	// CA is the ACME directory URL; empty means Let's Encrypt production.
	CA string `yaml:"ca"`
	// CARoot is a PEM file of roots to trust for the ACME server itself,
	// for private ACME CAs; empty means system roots.
	CARoot string `yaml:"ca_root"`
	// Storage keeps ACME accounts and certificates; empty means
	// /var/lib/l8tunnel/acme.
	Storage     string `yaml:"storage"`
	DNSProvider string `yaml:"dns_provider"`
	// DNSCredentials values may be written as ${ENV_VAR}.
	DNSCredentials map[string]string `yaml:"dns_credentials"`
}

// LoadServerFile reads a server YAML file.
func LoadServerFile(path string) (*ServerFile, error) {
	f := &ServerFile{}
	if err := decodeStrict(path, f); err != nil {
		return nil, err
	}
	return f, nil
}

// NewRelay builds the relay: its certificates (obtaining ACME
// certificates first), tokens and settings. ACME renewal runs until ctx
// ends.
func (f *ServerFile) NewRelay(ctx context.Context, logger *slog.Logger) (*relay.Server, error) {
	cfg, mgr, err := f.RelayConfig(ctx, logger)
	if err != nil {
		return nil, err
	}
	srv, err := relay.New(cfg)
	if err != nil {
		return nil, err
	}
	mgr.AllowHosts(srv.IsTunnelHost)
	return srv, nil
}

// RelayConfig builds the relay configuration and its certificate manager.
// relay.New validates the configuration further.
func (f *ServerFile) RelayConfig(ctx context.Context, logger *slog.Logger) (relay.Config, *certs.Manager, error) {
	cfg, err := f.relayConfig(logger)
	if err != nil {
		return relay.Config{}, nil, err
	}
	certCfg, err := f.certsConfig(cfg, logger)
	if err != nil {
		return relay.Config{}, nil, err
	}
	mgr, err := certs.New(ctx, certCfg)
	if err != nil {
		return relay.Config{}, nil, err
	}
	cfg.TLS = mgr.TLSConfig()
	cfg.HTTPChallenge = mgr.HTTPChallenge
	return cfg, mgr, nil
}

// certsConfig picks the certificate source: tls (static files) or acme.
func (f *ServerFile) certsConfig(cfg relay.Config, logger *slog.Logger) (certs.Config, error) {
	switch {
	case f.TLS != nil && f.ACME != nil:
		return certs.Config{}, fmt.Errorf("set either tls (certificate files) or acme, not both")
	case f.TLS != nil:
		return certs.Config{Mode: certs.ModeStatic, CertFile: f.TLS.Cert, KeyFile: f.TLS.Key}, nil
	case f.ACME == nil:
		return certs.Config{}, fmt.Errorf("either tls (certificate files) or acme is required")
	}
	if f.ACME.Mode == certs.ModeHTTP01 && cfg.HTTPAddr == "" {
		return certs.Config{}, fmt.Errorf("acme.mode %s needs the port 80 listener, but listen.http is off", certs.ModeHTTP01)
	}
	creds := map[string]string{}
	for key, value := range f.ACME.DNSCredentials {
		v, err := expandEnv("acme.dns_credentials."+key, value)
		if err != nil {
			return certs.Config{}, err
		}
		creds[key] = v
	}
	base := strings.ToLower(strings.TrimSuffix(f.BaseDomain, "."))
	controlSNI := strings.ToLower(f.ControlSNI)
	if controlSNI == "" {
		controlSNI = "connect." + base
	}
	return certs.Config{
		Mode:           f.ACME.Mode,
		Email:          f.ACME.Email,
		CA:             f.ACME.CA,
		CARootFile:     f.ACME.CARoot,
		HTTPListenAddr: cfg.HTTPAddr,
		Storage:        f.ACME.Storage,
		DNSProvider:    f.ACME.DNSProvider,
		DNSCredentials: creds,
		BaseDomain:     base,
		ControlSNI:     controlSNI,
		Logger:         logger,
	}, nil
}

// relayConfig builds everything except certificates.
func (f *ServerFile) relayConfig(logger *slog.Logger) (relay.Config, error) {
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
	httpListen := f.Listen.HTTP
	switch httpListen {
	case "":
		httpListen = defaultHTTPListen
	case listenOff:
		httpListen = ""
	}
	return relay.Config{
		ControlAddr:             listen,
		HTTPAddr:                httpListen,
		PublicHTTPSPort:         f.PublicHTTPSPort,
		DisableForwardedHeaders: f.ForwardedHeaders != nil && !*f.ForwardedHeaders,
		BaseDomain:              f.BaseDomain,
		ControlSNI:              f.ControlSNI,
		Tokens:                  tokens,
		PublicHost:              f.PublicHost,
		BindHost:                f.Bind,
		TCPPortMin:              portMin,
		TCPPortMax:              portMax,
		HeartbeatInterval:       f.HeartbeatInterval,
		NameGracePeriod:         f.NameGracePeriod,
		Logger:                  logger,
	}, nil
}
