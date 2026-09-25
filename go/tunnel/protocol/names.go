package protocol

import (
	"fmt"
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
