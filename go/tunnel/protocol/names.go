package protocol

import (
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var tunnelTypeNames = map[string]l8tunnel.TunnelType{
	"tcp":  l8tunnel.TunnelType_TUNNEL_TYPE_TCP,
	"ssh":  l8tunnel.TunnelType_TUNNEL_TYPE_SSH,
	"http": l8tunnel.TunnelType_TUNNEL_TYPE_HTTP,
	"tls":  l8tunnel.TunnelType_TUNNEL_TYPE_TLS,
}

// ParseTunnelType maps a config name (tcp, ssh, http, tls) to its type.
func ParseTunnelType(s string) (l8tunnel.TunnelType, error) {
	if typ, ok := tunnelTypeNames[strings.ToLower(s)]; ok {
		return typ, nil
	}
	return l8tunnel.TunnelType_TUNNEL_TYPE_UNSPECIFIED, fmt.Errorf("unknown tunnel type %q (want tcp, ssh, http or tls)", s)
}

// TunnelTypeName is the config name of a tunnel type ("" if invalid).
func TunnelTypeName(typ l8tunnel.TunnelType) string {
	for name, t := range tunnelTypeNames {
		if t == typ {
			return name
		}
	}
	return ""
}

// ParsePortRange parses "min-max" (or a single port) into its bounds.
func ParsePortRange(s string) (int, int, error) {
	lo, hi, found := strings.Cut(s, "-")
	if !found {
		hi = lo
	}
	first, err := strconv.Atoi(strings.TrimSpace(lo))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	last, err := strconv.Atoi(strings.TrimSpace(hi))
	if err != nil {
		return 0, 0, fmt.Errorf("invalid port range %q: %w", s, err)
	}
	if first < 1 || last > 65535 || first > last {
		return 0, 0, fmt.Errorf("invalid port range %q", s)
	}
	return first, last, nil
}

var dnsLabel = regexp.MustCompile(`^[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?$`)

// IsDNSLabel reports whether s is a lowercase DNS label.
func IsDNSLabel(s string) bool {
	return dnsLabel.MatchString(s)
}

// NormalizeDomain lowercases a domain name, drops a trailing dot, and
// checks it is a valid host name with at least two labels (no wildcards).
func NormalizeDomain(s string) (string, error) {
	d := strings.ToLower(strings.TrimSuffix(s, "."))
	labels := strings.Split(d, ".")
	if len(d) > 253 || len(labels) < 2 {
		return "", fmt.Errorf("domain %q must be a host name such as app.example.com", s)
	}
	for _, l := range labels {
		if !dnsLabel.MatchString(l) {
			return "", fmt.Errorf("domain %q is not a valid host name", s)
		}
	}
	return d, nil
}

// NormalizeTunnelDomain is NormalizeDomain for a tunnel's custom domain,
// which may also be a wildcard "*.<domain>" (the domain itself at least two
// labels). A wildcard covers every name under <domain>, at any depth.
func NormalizeTunnelDomain(s string) (string, error) {
	rest, wild := strings.CutPrefix(s, "*.")
	d, err := NormalizeDomain(rest)
	if err != nil {
		return "", fmt.Errorf("domain %q must be a host name such as app.example.com, or a wildcard such as *.example.com", s)
	}
	if wild {
		return "*." + d, nil
	}
	return d, nil
}

// IsWildcardDomain reports whether d is a wildcard "*.<domain>".
func IsWildcardDomain(d string) bool {
	return strings.HasPrefix(d, "*.")
}

// WildcardsOf lists the wildcard domains that cover host, closest first:
// a.b.example.com gives *.b.example.com, *.example.com.
func WildcardsOf(host string) []string {
	var out []string
	labels := strings.Split(host, ".")
	for i := 1; i+2 <= len(labels); i++ {
		out = append(out, "*."+strings.Join(labels[i:], "."))
	}
	return out
}
