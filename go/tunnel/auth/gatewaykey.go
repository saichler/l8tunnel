package auth

import (
	"fmt"
	"path"
	"strings"
	"time"

	"golang.org/x/crypto/ssh"
)

// GatewayKey is a public key allowed to use the SSH jump gateway.
type GatewayKey struct {
	Name        string `json:"name"`
	PublicKey   string `json:"public_key"` // authorized_keys format
	Fingerprint string `json:"fingerprint"`
	// Tunnels are path.Match patterns of tunnel names the key may reach.
	// Tunnels with an access token also need their exact name listed.
	Tunnels []string  `json:"tunnels"`
	Created time.Time `json:"created"`
}

// NewGatewayKey parses an authorized_keys line and validates the grants.
func NewGatewayKey(name, authorizedKey string, tunnels []string) (*GatewayKey, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("key name %q must be 1-64 letters, digits, '.', '_' or '-'", name)
	}
	key, _, _, _, err := ssh.ParseAuthorizedKey([]byte(strings.TrimSpace(authorizedKey)))
	if err != nil {
		return nil, fmt.Errorf("public key: %w", err)
	}
	if len(tunnels) == 0 {
		return nil, fmt.Errorf("grant at least one tunnel name or pattern")
	}
	for _, p := range tunnels {
		if _, err := path.Match(p, ""); err != nil {
			return nil, fmt.Errorf("invalid tunnel pattern %q: %w", p, err)
		}
	}
	return &GatewayKey{
		Name:        name,
		PublicKey:   strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key))),
		Fingerprint: ssh.FingerprintSHA256(key),
		Tunnels:     tunnels,
		Created:     time.Now().UTC(),
	}, nil
}

// Allows reports whether the key may reach a tunnel. explicitOnly (for
// tunnels with an access token) requires the exact name, not a pattern.
func (k *GatewayKey) Allows(tunnel string, explicitOnly bool) bool {
	for _, p := range k.Tunnels {
		if explicitOnly {
			if p == tunnel {
				return true
			}
			continue
		}
		if ok, _ := path.Match(p, tunnel); ok {
			return true
		}
	}
	return false
}
