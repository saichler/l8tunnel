// Package certs provides the relay's TLS certificates: from files
// (static), or from an ACME CA such as Let's Encrypt, either as a wildcard
// through a DNS provider (dns01) or per host through HTTP challenges on
// port 80 (http01).
package certs

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"

	"github.com/caddyserver/certmagic"

	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// Modes.
const (
	ModeStatic = "static"
	ModeDNS01  = "dns01"
	ModeHTTP01 = "http01"
)

// DefaultStorage is where ACME accounts and certificates are kept.
const DefaultStorage = "/var/lib/l8tunnel/acme"

// Config configures a Manager.
type Config struct {
	Mode string

	// CertFile and KeyFile are the static certificate (ModeStatic).
	CertFile, KeyFile string

	// Email is the ACME account contact (required for ACME modes).
	Email string
	// CA is the ACME directory URL; empty means Let's Encrypt production.
	CA string
	// CARootFile is a PEM file of roots to trust for the ACME server
	// itself (a private CA such as step-ca); empty means system roots.
	CARootFile string
	// Storage is the directory for ACME state; empty means DefaultStorage.
	Storage string
	// HTTPListenAddr is the relay's plain HTTP listener (ModeHTTP01). At
	// startup, before the relay listens, certmagic serves the challenges on
	// this address itself; afterwards they reach it through HTTPChallenge.
	HTTPListenAddr string
	// DNSProvider and DNSCredentials configure ModeDNS01, for example
	// "cloudflare" with {"api_token": "..."}.
	DNSProvider    string
	DNSCredentials map[string]string

	// BaseDomain and ControlSNI are the names certificates must cover.
	BaseDomain string
	ControlSNI string

	Logger *slog.Logger
}

// Manager serves the relay's certificates.
type Manager struct {
	tls       *tls.Config
	issuer    *certmagic.ACMEIssuer // nil in ModeStatic
	mu        sync.Mutex
	allowHost func(host string) bool
}

// New validates cfg and prepares the certificates. In the ACME modes it
// obtains (or loads from storage) the certificates it needs up front, so a
// misconfiguration stops the relay from starting instead of surfacing on
// the first client connection. Certificate renewal runs until ctx ends.
func New(ctx context.Context, cfg Config) (*Manager, error) {
	switch cfg.Mode {
	case ModeStatic:
		tlsCfg, err := transport.ServerTLSConfig(cfg.CertFile, cfg.KeyFile)
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		return &Manager{tls: tlsCfg}, nil
	case ModeDNS01, ModeHTTP01:
		return newACME(ctx, cfg)
	}
	return nil, fmt.Errorf("acme.mode %q must be %s or %s", cfg.Mode, ModeDNS01, ModeHTTP01)
}

func newACME(ctx context.Context, cfg Config) (*Manager, error) {
	// Validate everything before touching the network or storage.
	if cfg.Email == "" {
		return nil, fmt.Errorf("acme.email is required")
	}
	if cfg.BaseDomain == "" || cfg.ControlSNI == "" {
		return nil, fmt.Errorf("certs: BaseDomain and ControlSNI are required")
	}
	var provider certmagic.DNSProvider
	var challengeHost string
	var challengePort int
	switch cfg.Mode {
	case ModeDNS01:
		p, err := newDNSProvider(cfg.DNSProvider, cfg.DNSCredentials)
		if err != nil {
			return nil, err
		}
		provider = p
	case ModeHTTP01:
		if cfg.DNSProvider != "" || len(cfg.DNSCredentials) > 0 {
			return nil, fmt.Errorf("acme.dns_provider and acme.dns_credentials apply only to mode %s", ModeDNS01)
		}
		host, port, err := net.SplitHostPort(cfg.HTTPListenAddr)
		if err != nil {
			return nil, fmt.Errorf("acme.mode %s needs the port 80 listener (listen.http): %w", ModeHTTP01, err)
		}
		if challengePort, err = strconv.Atoi(port); err != nil || challengePort == 0 {
			return nil, fmt.Errorf("listen.http %q needs a fixed port for acme.mode %s", cfg.HTTPListenAddr, ModeHTTP01)
		}
		challengeHost = host
	}
	var roots *x509.CertPool
	if cfg.CARootFile != "" {
		pem, err := os.ReadFile(cfg.CARootFile)
		if err != nil {
			return nil, fmt.Errorf("acme.ca_root: %w", err)
		}
		roots = x509.NewCertPool()
		if !roots.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("acme.ca_root %s contains no PEM certificates", cfg.CARootFile)
		}
	}
	if cfg.Storage == "" {
		cfg.Storage = DefaultStorage
	}
	if cfg.CA == "" {
		cfg.CA = certmagic.LetsEncryptProductionCA
	}

	logger := newZapLogger(cfg.Logger.With("component", "acme"))
	m := &Manager{}
	var magic *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(certmagic.Certificate) (*certmagic.Config, error) { return magic, nil },
		Logger:           logger,
	})
	magic = certmagic.New(cache, certmagic.Config{
		Storage: &certmagic.FileStorage{Path: cfg.Storage},
		Logger:  logger,
	})
	issuer := certmagic.ACMEIssuer{
		CA:                      cfg.CA,
		Email:                   cfg.Email,
		Agreed:                  true,
		DisableTLSALPNChallenge: true,
		ListenHost:              challengeHost,
		AltHTTPPort:             challengePort,
		TrustedRoots:            roots,
		Logger:                  logger,
	}

	var names []string
	if cfg.Mode == ModeDNS01 {
		issuer.DisableHTTPChallenge = true
		issuer.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider}}
		names = []string{"*." + cfg.BaseDomain}
		if !coveredByWildcard(cfg.ControlSNI, cfg.BaseDomain) {
			names = append(names, cfg.ControlSNI)
		}
	} else {
		names = []string{cfg.ControlSNI}
	}
	m.issuer = certmagic.NewACMEIssuer(magic, issuer)
	magic.Issuers = []certmagic.Issuer{m.issuer}

	// ManageSync must run before OnDemand is set: with OnDemand set,
	// certmagic only allowlists the names and defers obtaining them to the
	// first handshake, which would hide a misconfiguration until then.
	if err := magic.ManageSync(ctx, names); err != nil {
		cache.Stop()
		return nil, fmt.Errorf("obtain certificates for %s from %s: %w", strings.Join(names, ", "), cfg.CA, err)
	}
	if cfg.Mode == ModeHTTP01 {
		// Tunnel hosts get certificates on demand, but only for names a
		// tunnel has reserved, so strangers can't make the relay request
		// certificates for arbitrary names.
		magic.OnDemand = &certmagic.OnDemandConfig{
			DecisionFunc: func(_ context.Context, name string) error {
				if m.hostAllowed(name) {
					return nil
				}
				return fmt.Errorf("no tunnel reserves %q", name)
			},
		}
	}
	go func() {
		<-ctx.Done()
		cache.Stop()
	}()

	base := magic.TLSConfig()
	m.tls = &tls.Config{GetCertificate: base.GetCertificate, MinVersion: tls.VersionTLS12}
	return m, nil
}

// coveredByWildcard reports whether *.base covers name (one label deep).
func coveredByWildcard(name, base string) bool {
	label, ok := strings.CutSuffix(name, "."+base)
	return ok && label != "" && !strings.Contains(label, ".")
}

// TLSConfig is the base TLS config for the relay (relay.Config.TLS).
func (m *Manager) TLSConfig() *tls.Config {
	return m.tls
}

// HTTPChallenge answers ACME HTTP-01 challenges on the relay's plain HTTP
// listener and passes every other request to next
// (relay.Config.HTTPChallenge).
func (m *Manager) HTTPChallenge(next http.Handler) http.Handler {
	if m.issuer == nil {
		return next
	}
	return m.issuer.HTTPChallengeHandler(next)
}

// AllowHosts sets the policy for on-demand certificates (mode http01):
// only host names it approves get one. Until it is set, none do.
func (m *Manager) AllowHosts(allow func(host string) bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.allowHost = allow
}

func (m *Manager) hostAllowed(host string) bool {
	m.mu.Lock()
	allow := m.allowHost
	m.mu.Unlock()
	return allow != nil && allow(host)
}
