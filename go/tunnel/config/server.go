package config

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/tunnel/oidc"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"golang.org/x/crypto/ssh"
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
	// Storage is the directory for the database (tokens, reservations)
	// and, by default, ACME state; empty means /var/lib/l8tunnel.
	Storage string `yaml:"storage"`
	Admin   struct {
		// Socket is the admin API's Unix socket; empty means
		// /run/l8tunnel/admin.sock.
		Socket string `yaml:"socket"`
	} `yaml:"admin"`
	Log LogFile `yaml:"log"`
	// AccessLog logs every request of HTTP tunnels (method, host, path,
	// status, bytes, duration, client).
	AccessLog bool `yaml:"access_log"`
	// Metrics serves Prometheus metrics over plain HTTP.
	Metrics struct {
		// Listen is an address such as 127.0.0.1:9100; empty disables it.
		Listen string `yaml:"listen"`
	} `yaml:"metrics"`
	// SSHGateway enables the SSH jump gateway (ssh -J).
	SSHGateway *struct {
		// Listen is the gateway's address, e.g. ":2222".
		Listen string `yaml:"listen"`
		// HostKey is the gateway's private host key; empty means
		// <storage>/gateway_host_key, generated on first start.
		HostKey string `yaml:"host_key"`
	} `yaml:"ssh_gateway"`
	// OIDC enables "sign in with ..." for http tunnels.
	OIDC *OIDCFile `yaml:"oidc"`
	// RateLimits are per client IP; zero values mean the relay defaults.
	RateLimits struct {
		ConnectionsPerSecond  float64 `yaml:"connections_per_second"`
		ConnectionsBurst      int     `yaml:"connections_burst"`
		AuthFailuresPerMinute int     `yaml:"auth_failures_per_minute"`
	} `yaml:"rate_limits"`
	// HeartbeatInterval and NameGracePeriod are durations such as "15s";
	// empty means the relay defaults (15s and 5m).
	HeartbeatInterval time.Duration `yaml:"heartbeat_interval"`
	NameGracePeriod   time.Duration `yaml:"name_grace_period"`
}

// OIDCFile is the oidc block of server.yaml.
type OIDCFile struct {
	// AuthHost is the login host; empty means auth.<base_domain>.
	AuthHost string `yaml:"auth_host"`
	// SessionTTL is how long a login lasts; empty means 12h.
	SessionTTL time.Duration `yaml:"session_ttl"`
	// Providers by name; tunnels pick one with oidc.provider.
	Providers map[string]struct {
		Issuer       string   `yaml:"issuer"`
		ClientID     string   `yaml:"client_id"`
		ClientSecret string   `yaml:"client_secret"` // may be ${ENV_VAR}
		Scopes       []string `yaml:"scopes"`
	} `yaml:"providers"`
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
	// <storage>/acme.
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

// DefaultStorage is the relay's state directory.
const DefaultStorage = "/var/lib/l8tunnel"

// StorageDir is the relay's state directory.
func (f *ServerFile) StorageDir() string {
	if f.Storage == "" {
		return DefaultStorage
	}
	return f.Storage
}

// DatabasePath is the relay's database file.
func (f *ServerFile) DatabasePath() string {
	return filepath.Join(f.StorageDir(), "l8tunnel.db")
}

// AdminSocket is the admin API's Unix socket.
func (f *ServerFile) AdminSocket() string {
	if f.Admin.Socket == "" {
		return admin.DefaultServerSocket
	}
	return f.Admin.Socket
}

// NewRelay builds the relay on an open store: its certificates (obtaining
// ACME certificates first), tokens, reservations and settings. ACME
// renewal runs until ctx ends.
func (f *ServerFile) NewRelay(ctx context.Context, logger *slog.Logger, st *store.Store, version string) (*relay.Server, error) {
	cfg, mgr, err := f.RelayConfig(ctx, logger)
	if err != nil {
		return nil, err
	}
	cfg.Version = version
	cfg.Tokens = st
	ca, err := st.AgentCA()
	if err != nil {
		return nil, fmt.Errorf("agent CA: %w", err)
	}
	cfg.AgentCA = ca.Certificate()
	reservations, err := st.Reservations()
	if err != nil {
		return nil, err
	}
	for _, r := range reservations {
		cfg.Reservations = append(cfg.Reservations, relay.PermanentReservation{Name: r.Name, TokenID: r.TokenID, Port: r.Port})
	}
	tokens, err := st.Tokens()
	if err != nil {
		return nil, err
	}
	if len(tokens) == 0 {
		logger.Warn("no agent tokens yet; create one with: l8tunnel-server token create --name <name>")
	}
	if g := f.SSHGateway; g != nil {
		if g.Listen == "" {
			return nil, fmt.Errorf("ssh_gateway.listen is required")
		}
		path := g.HostKey
		if path == "" {
			path = filepath.Join(f.StorageDir(), "gateway_host_key")
		}
		signer, err := loadOrCreateHostKey(path)
		if err != nil {
			return nil, fmt.Errorf("ssh_gateway.host_key: %w", err)
		}
		cfg.SSHGateway = &relay.GatewayConfig{Listen: g.Listen, HostKey: signer, Keys: st}
	}
	var login *oidc.Service
	if f.OIDC != nil {
		if login, err = f.oidcService(st, logger); err != nil {
			return nil, err
		}
		cfg.Login = login
	}
	srv, err := relay.New(cfg)
	if err != nil {
		return nil, err
	}
	mgr.AllowHosts(srv.IsTunnelHost)
	if login != nil {
		login.Bind(oidc.Binding{RuleFor: srv.OIDCRuleFor, HTTPSPort: srv.PublicHTTPSPort})
	}
	return srv, nil
}

// oidcService builds the OIDC login service from the oidc block.
func (f *ServerFile) oidcService(st *store.Store, logger *slog.Logger) (*oidc.Service, error) {
	key, err := st.SessionKey()
	if err != nil {
		return nil, fmt.Errorf("oidc: session key: %w", err)
	}
	authHost := strings.ToLower(f.OIDC.AuthHost)
	if authHost == "" {
		authHost = "auth." + strings.ToLower(strings.TrimSuffix(f.BaseDomain, "."))
	}
	providers := map[string]oidc.ProviderConfig{}
	for name, p := range f.OIDC.Providers {
		secret, err := expandEnv("oidc.providers."+name+".client_secret", p.ClientSecret)
		if err != nil {
			return nil, err
		}
		providers[name] = oidc.ProviderConfig{Issuer: p.Issuer, ClientID: p.ClientID, ClientSecret: secret, Scopes: p.Scopes}
	}
	return oidc.New(oidc.Config{
		AuthHost:   authHost,
		Providers:  providers,
		SessionTTL: f.OIDC.SessionTTL,
		Key:        key,
		ErrorPage:  httpproxy.WriteErrorPage,
		Logger:     logger,
	})
}

// RelayConfig builds the relay configuration (without its token store)
// and its certificate manager. relay.New validates it further.
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
	cfg.CanServeHost = mgr.CanServe
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
		Storage:        f.acmeStorage(),
		DNSProvider:    f.ACME.DNSProvider,
		DNSCredentials: creds,
		BaseDomain:     base,
		ControlSNI:     controlSNI,
		Logger:         logger,
	}, nil
}

// relayConfig builds everything except certificates.
func (f *ServerFile) relayConfig(logger *slog.Logger) (relay.Config, error) {
	portRange := f.TCPPortRange
	if portRange == "" {
		portRange = defaultTCPPortRange
	}
	portMin, portMax, err := protocol.ParsePortRange(portRange)
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
		AccessLog:               f.AccessLog,
		BaseDomain:              f.BaseDomain,
		ControlSNI:              f.ControlSNI,
		RateLimits: relay.RateLimits{
			ConnectionsPerSecond:  f.RateLimits.ConnectionsPerSecond,
			ConnectionsBurst:      f.RateLimits.ConnectionsBurst,
			AuthFailuresPerMinute: f.RateLimits.AuthFailuresPerMinute,
		},
		PublicHost:        f.PublicHost,
		BindHost:          f.Bind,
		TCPPortMin:        portMin,
		TCPPortMax:        portMax,
		HeartbeatInterval: f.HeartbeatInterval,
		NameGracePeriod:   f.NameGracePeriod,
		Logger:            logger,
	}, nil
}

// acmeStorage is the ACME state directory: acme.storage, or <storage>/acme.
func (f *ServerFile) acmeStorage() string {
	if f.ACME.Storage != "" {
		return f.ACME.Storage
	}
	return filepath.Join(f.StorageDir(), "acme")
}

// loadOrCreateHostKey loads an SSH host key, generating an ed25519 key
// (mode 0600) if the file doesn't exist yet.
func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return nil, err
		}
		block, err := ssh.MarshalPrivateKey(priv, "l8tunnel gateway")
		if err != nil {
			return nil, err
		}
		data = pem.EncodeToMemory(block)
		if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, data, 0o600); err != nil {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	}
	return ssh.ParsePrivateKey(data)
}
