package certs

import (
	"fmt"
	"sort"
	"strings"

	"github.com/caddyserver/certmagic"
	"github.com/libdns/cloudflare"
)

// dnsProviderFactory builds a DNS provider from acme.dns_credentials.
type dnsProviderFactory func(creds map[string]string) (certmagic.DNSProvider, error)

// dnsProviders are the supported DNS-01 providers. Adding one means adding
// its libdns module and a factory here.
var dnsProviders = map[string]dnsProviderFactory{
	"cloudflare": newCloudflare,
}

func newDNSProvider(name string, creds map[string]string) (certmagic.DNSProvider, error) {
	if name == "" {
		return nil, fmt.Errorf("acme.dns_provider is required for mode %s (supported: %s)", ModeDNS01, supportedProviders())
	}
	factory, ok := dnsProviders[name]
	if !ok {
		return nil, fmt.Errorf("acme.dns_provider %q is not supported (supported: %s)", name, supportedProviders())
	}
	return factory(creds)
}

func supportedProviders() string {
	names := make([]string, 0, len(dnsProviders))
	for name := range dnsProviders {
		names = append(names, name)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

// requireCredentials checks that creds has every required key and nothing
// else, so a typo fails at startup instead of at the first renewal.
func requireCredentials(provider string, creds map[string]string, required ...string) error {
	allowed := map[string]bool{}
	for _, key := range required {
		allowed[key] = true
		if creds[key] == "" {
			return fmt.Errorf("acme.dns_credentials.%s is required for %s", key, provider)
		}
	}
	for key := range creds {
		if !allowed[key] {
			return fmt.Errorf("acme.dns_credentials.%s is not a %s credential (want: %s)",
				key, provider, strings.Join(required, ", "))
		}
	}
	return nil
}

// newCloudflare uses an API token with Zone:Read and DNS:Edit permissions.
func newCloudflare(creds map[string]string) (certmagic.DNSProvider, error) {
	if err := requireCredentials("cloudflare", creds, "api_token"); err != nil {
		return nil, err
	}
	return &cloudflare.Provider{APIToken: creds["api_token"]}, nil
}
