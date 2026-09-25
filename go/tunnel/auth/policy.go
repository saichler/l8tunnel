package auth

import (
	"fmt"
	"path"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

// Policy limits what an agent token may register. The zero value allows
// everything the relay allows.
type Policy struct {
	// Names are path.Match patterns for tunnel names, e.g. "app" or
	// "dev-*"; empty allows any name. Relay-assigned names must match too.
	Names []string `json:"names,omitempty"`
	// Types are tunnel types (tcp, ssh, http, tls); empty allows all.
	Types []string `json:"types,omitempty"`
	// MaxTunnels caps the token's connected tunnels; 0 means no cap.
	MaxTunnels int `json:"max_tunnels,omitempty"`
	// Ports is a "min-max" range the token's tcp/ssh public ports must fall
	// in (requested or allocated); empty means the relay's whole range.
	Ports string `json:"ports,omitempty"`
	// RequireCert refuses agents that don't present one of the token's
	// client certificates (the token string alone isn't enough).
	RequireCert bool `json:"require_cert,omitempty"`
}

// Validate checks the policy's patterns, types and port range.
func (p Policy) Validate() error {
	for _, pattern := range p.Names {
		if _, err := path.Match(pattern, ""); err != nil {
			return fmt.Errorf("invalid name pattern %q: %w", pattern, err)
		}
	}
	for _, typ := range p.Types {
		if _, err := protocol.ParseTunnelType(typ); err != nil {
			return err
		}
	}
	if p.MaxTunnels < 0 {
		return fmt.Errorf("max tunnels must not be negative")
	}
	if p.Ports != "" {
		if _, _, err := protocol.ParsePortRange(p.Ports); err != nil {
			return err
		}
	}
	return nil
}

// AllowsName reports whether the policy allows a tunnel name.
func (p Policy) AllowsName(name string) bool {
	if len(p.Names) == 0 {
		return true
	}
	for _, pattern := range p.Names {
		if ok, _ := path.Match(pattern, name); ok {
			return true
		}
	}
	return false
}

// AllowsType reports whether the policy allows a tunnel type name.
func (p Policy) AllowsType(typ string) bool {
	if len(p.Types) == 0 {
		return true
	}
	for _, t := range p.Types {
		if t == typ {
			return true
		}
	}
	return false
}

// PortRange narrows [min, max] to the policy's port range. ok is false
// when the two don't overlap.
func (p Policy) PortRange(min, max int) (lo, hi int, ok bool) {
	if p.Ports == "" {
		return min, max, true
	}
	// Validate has checked the range.
	plo, phi, _ := protocol.ParsePortRange(p.Ports)
	lo, hi = maxInt(min, plo), minInt(max, phi)
	return lo, hi, lo <= hi
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
