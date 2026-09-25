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
	"time"

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
	issuer    *certmagic.ACMEIssuer // answers HTTP-01; nil when nothing uses it
	canServe  func(host string) error
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
		leaf, err := x509.ParseCertificate(tlsCfg.Certificates[0].Certificate[0])
		if err != nil {
			return nil, fmt.Errorf("tls: %w", err)
		}
		if time.Now().After(leaf.NotAfter) {
			return nil, fmt.Errorf("tls: the certificate %s expired on %s", cfg.CertFile, leaf.NotAfter.Format(time.RFC3339))
		}
		go watchExpiry(ctx, leaf, cfg.CertFile, cfg.Logger)
		return &Manager{tls: tlsCfg, canServe: func(host string) error {
			if leaf.VerifyHostname(host) != nil {
				return fmt.Errorf("the relay's certificate (tls.cert) doesn't cover %s", host)
			}
			return nil
		}}, nil
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
	}
	// HTTP-01 is served on the relay's port 80 listener: required for
	// http01, and enables custom domains in dns01.
	challengeHost, challengePort, httpErr := parseChallengeAddr(cfg.HTTPListenAddr)
	if cfg.Mode == ModeHTTP01 && httpErr != nil {
		return nil, fmt.Errorf("acme.mode %s: %w", ModeHTTP01, httpErr)
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
	underBase := func(name string) bool {
		return name == cfg.ControlSNI || name == "*."+cfg.BaseDomain || coveredByWildcard(name, cfg.BaseDomain)
	}
	// Two configs can share the cache: magic for the relay's own names, and
	// in dns01 mode custom for custom domains (HTTP-01 on demand).
	var magic, custom *certmagic.Config
	cache := certmagic.NewCache(certmagic.CacheOptions{
		GetConfigForCert: func(c certmagic.Certificate) (*certmagic.Config, error) {
			for _, n := range c.Names {
				if custom != nil && !underBase(n) {
					return custom, nil
				}
			}
			return magic, nil
		},
		Logger: logger,
	})
	storage := &certmagic.FileStorage{Path: cfg.Storage}
	newIssuer := func() certmagic.ACMEIssuer {
		return certmagic.ACMEIssuer{
			CA:                      cfg.CA,
			Email:                   cfg.Email,
			Agreed:                  true,
			DisableTLSALPNChallenge: true,
			ListenHost:              challengeHost,
			AltHTTPPort:             challengePort,
			TrustedRoots:            roots,
			Logger:                  logger,
		}
	}
	// Tunnel hosts get certificates on demand, but only for names a tunnel
	// has reserved, so strangers can't make the relay request certificates
	// for arbitrary names.
	onDemand := &certmagic.OnDemandConfig{
		DecisionFunc: func(_ context.Context, name string) error {
			if m.hostAllowed(name) {
				return nil
			}
			return fmt.Errorf("no tunnel reserves %q", name)
		},
	}

	magic = certmagic.New(cache, certmagic.Config{Storage: storage, Logger: logger})
	baseIssuer := newIssuer()
	var names []string
	if cfg.Mode == ModeDNS01 {
		baseIssuer.DisableHTTPChallenge = true
		baseIssuer.DNS01Solver = &certmagic.DNS01Solver{DNSManager: certmagic.DNSManager{DNSProvider: provider}}
		names = []string{"*." + cfg.BaseDomain}
		if !coveredByWildcard(cfg.ControlSNI, cfg.BaseDomain) {
			names = append(names, cfg.ControlSNI)
		}
	} else {
		names = []string{cfg.ControlSNI}
	}
	iss := certmagic.NewACMEIssuer(magic, baseIssuer)
	magic.Issuers = []certmagic.Issuer{iss}

	// ManageSync must run before OnDemand is set: with OnDemand set,
	// certmagic only allowlists the names and defers obtaining them to the
	// first handshake, which would hide a misconfiguration until then.
	if err := magic.ManageSync(ctx, names); err != nil {
		cache.Stop()
		return nil, fmt.Errorf("obtain certificates for %s from %s: %w", strings.Join(names, ", "), cfg.CA, err)
	}

	switch {
	case cfg.Mode == ModeHTTP01:
		magic.OnDemand = onDemand
		m.issuer = iss
		m.canServe = func(string) error { return nil }
	case httpErr == nil:
		custom = certmagic.New(cache, certmagic.Config{Storage: storage, Logger: logger, OnDemand: onDemand})
		m.issuer = certmagic.NewACMEIssuer(custom, newIssuer())
		custom.Issuers = []certmagic.Issuer{m.issuer}
		m.canServe = func(string) error { return nil }
	default:
		m.canServe = func(host string) error {
			return fmt.Errorf("custom domains with acme.mode %s need listen.http for HTTP-01 (%v)", ModeDNS01, httpErr)
		}
	}
	go func() {
		<-ctx.Done()
		cache.Stop()
	}()

	baseGet := magic.TLSConfig().GetCertificate
	var customGet func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	if custom != nil {
		customGet = custom.TLSConfig().GetCertificate
	}
	m.tls = &tls.Config{MinVersion: tls.VersionTLS12, GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		if customGet != nil && !underBase(strings.ToLower(hello.ServerName)) {
			return customGet(hello)
		}
		return baseGet(hello)
	}}
	return m, nil
}

// parseChallengeAddr checks listen.http is usable for HTTP-01.
func parseChallengeAddr(addr string) (string, int, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, fmt.Errorf("needs the port 80 listener (listen.http): %w", err)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p == 0 {
		return "", 0, fmt.Errorf("listen.http %q needs a fixed port", addr)
	}
	return host, p, nil
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

// CanServe reports whether the manager can present a certificate for a
// custom domain (relay.Config.CanServeHost).
func (m *Manager) CanServe(host string) error {
	return m.canServe(host)
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

// ExpiryWarning is how long before a static certificate expires the relay
// starts warning, daily, in its log.
const ExpiryWarning = 21 * 24 * time.Hour

// watchExpiry logs a warning daily once a static certificate is within
// ExpiryWarning of expiring, and an error once it has expired. Static
// certificates don't renew themselves.
func watchExpiry(ctx context.Context, leaf *x509.Certificate, file string, logger *slog.Logger) {
	if logger == nil {
		logger = slog.Default()
	}
	check := func() {
		left := time.Until(leaf.NotAfter)
		switch {
		case left <= 0:
			logger.Error("the TLS certificate has expired; clients are refusing connections: replace it and restart",
				"file", file, "expired", leaf.NotAfter.Format(time.RFC3339))
		case left < ExpiryWarning:
			logger.Warn("the TLS certificate expires soon: renew it and restart the relay",
				"file", file, "expires", leaf.NotAfter.Format(time.RFC3339), "days_left", int(left.Hours()/24))
		}
	}
	check()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			check()
		}
	}
}
