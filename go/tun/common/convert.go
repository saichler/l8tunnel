package common

import (
	"fmt"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/tun"
)

var tunnelTypeNames = map[tun.TunTunnelType]string{
	tun.TunTunnelType_TUN_TUNNEL_TYPE_TCP:  "tcp",
	tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH:  "ssh",
	tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP: "http",
	tun.TunTunnelType_TUN_TUNNEL_TYPE_TLS:  "tls",
}

// TunnelTypeName is the relay's name for a tunnel type ("" if unspecified).
func TunnelTypeName(t tun.TunTunnelType) string {
	return tunnelTypeNames[t]
}

// TunnelTypeOf maps the relay's name back ("tcp" -> TUN_TUNNEL_TYPE_TCP).
func TunnelTypeOf(name string) (tun.TunTunnelType, error) {
	for t, n := range tunnelTypeNames {
		if n == name {
			return t, nil
		}
	}
	return tun.TunTunnelType_TUN_TUNNEL_TYPE_UNSPECIFIED, fmt.Errorf("unknown tunnel type %q", name)
}

// PolicyToAuth converts a token policy to the relay's policy.
func PolicyToAuth(p *tun.TunTokenPolicy) (auth.Policy, error) {
	if p == nil {
		return auth.Policy{}, nil
	}
	out := auth.Policy{
		Names:       append([]string(nil), p.Names...),
		MaxTunnels:  int(p.MaxTunnels),
		Ports:       p.Ports,
		RequireCert: p.RequireCert,
		Domains:     append([]string(nil), p.Domains...),
	}
	for _, t := range p.Types {
		name := TunnelTypeName(t)
		if name == "" {
			return auth.Policy{}, fmt.Errorf("policy: invalid tunnel type %s", t)
		}
		out.Types = append(out.Types, name)
	}
	return out, nil
}

// PolicyFromAuth converts the relay's policy to a token policy.
func PolicyFromAuth(p auth.Policy) (*tun.TunTokenPolicy, error) {
	out := &tun.TunTokenPolicy{
		Names:       append([]string(nil), p.Names...),
		MaxTunnels:  int32(p.MaxTunnels),
		Ports:       p.Ports,
		RequireCert: p.RequireCert,
		Domains:     append([]string(nil), p.Domains...),
	}
	for _, name := range p.Types {
		t, err := TunnelTypeOf(name)
		if err != nil {
			return nil, err
		}
		out.Types = append(out.Types, t)
	}
	return out, nil
}

// TokenRecord builds the relay's token record from a stored token and the
// serials of its agent certificates that aren't revoked.
func TokenRecord(t *tun.TunToken, certSerials []string) (*auth.TokenRecord, error) {
	policy, err := PolicyToAuth(t.Policy)
	if err != nil {
		return nil, err
	}
	return &auth.TokenRecord{
		ID:          t.TokenId,
		Name:        t.Name,
		Hash:        []byte(t.SecretHash),
		Created:     time.Unix(t.CreatedAt, 0).UTC(),
		Policy:      policy,
		CertSerials: certSerials,
	}, nil
}
