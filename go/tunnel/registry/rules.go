// Package registry holds the rules for claiming tunnel names and public
// ports: which names are valid or reserved, which ports a token may use,
// and how a new registration relates to an existing holder of the name.
// The relay's in-memory registry applies them on one relay; the
// cluster-wide live table applies the same rules across relays.
package registry

import (
	"errors"
	"fmt"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

var (
	// ErrNameTaken: another token (or another agent of the same token)
	// holds the name.
	ErrNameTaken = errors.New("name taken")
	// ErrMaxTunnels: the token already has its maximum of active tunnels.
	ErrMaxTunnels = errors.New("token's tunnel limit reached")
	// ErrPortTaken: another tunnel holds the port.
	ErrPortTaken = errors.New("port taken")
	// ErrInvalidName: the name isn't a lowercase DNS label.
	ErrInvalidName = errors.New("invalid tunnel name")
	// ErrReservedName: the name belongs to the relay itself.
	ErrReservedName = errors.New("reserved tunnel name")
	// ErrPortOutsideRange: the port is outside the relay's range.
	ErrPortOutsideRange = errors.New("port outside the relay's range")
	// ErrPortNotAllowed: the token's policy doesn't allow the port.
	ErrPortNotAllowed = errors.New("port not allowed by the token's policy")
)

// ruleError carries a message for the agent or operator and the sentinel
// error it matches with errors.Is.
type ruleError struct {
	kind error
	msg  string
}

func (e *ruleError) Error() string { return e.msg }
func (e *ruleError) Unwrap() error { return e.kind }

func fail(kind error, format string, args ...interface{}) error {
	return &ruleError{kind: kind, msg: fmt.Sprintf(format, args...)}
}

// Rules are the relay-wide settings the name and port rules depend on.
type Rules struct {
	// BaseDomain: tunnel "db" is db.<BaseDomain>.
	BaseDomain string
	// ControlSNI is the agents' host name; its label can't be a tunnel.
	ControlSNI string
	// AuthHost is the OIDC login host ("" when OIDC is off); its label
	// can't be a tunnel.
	AuthHost string
	// ReservedNames can't be tunnel names (e.g. "www").
	ReservedNames []string
	// PortMin and PortMax bound the public ports of tcp/ssh tunnels.
	PortMin, PortMax int
}

// ValidName reports whether name is a lowercase DNS label, which tunnel
// names must be because tunnels are reachable as <name>.<base-domain>.
func ValidName(name string) bool {
	return protocol.IsDNSLabel(name)
}

// CheckName returns an error matching ErrInvalidName or ErrReservedName,
// or nil.
func (r Rules) CheckName(name string) error {
	if !ValidName(name) {
		return fail(ErrInvalidName, "tunnel name %q must be a lowercase DNS label", name)
	}
	if r.IsReserved(name) {
		return fail(ErrReservedName, "tunnel name %q is reserved for the relay", name)
	}
	return nil
}

// IsReserved reports whether name belongs to the relay: the control host,
// the OIDC login host, or an operator-reserved name.
func (r Rules) IsReserved(name string) bool {
	host := name + "." + r.BaseDomain
	if host == r.ControlSNI || (r.AuthHost != "" && host == r.AuthHost) {
		return true
	}
	for _, n := range r.ReservedNames {
		if n == name {
			return true
		}
	}
	return false
}

// TunnelName extracts the tunnel name from <name>.<base-domain>, or
// returns "" when host isn't a tunnel host name.
func (r Rules) TunnelName(host string) string {
	name, ok := strings.CutSuffix(host, "."+r.BaseDomain)
	if !ok || !ValidName(name) {
		return ""
	}
	return name
}

// CheckReservation validates an operator reservation of name, optionally
// with a fixed public port (0 = none).
func (r Rules) CheckReservation(name string, port int) error {
	if err := r.CheckName(name); err != nil {
		return err
	}
	if port != 0 && (port < r.PortMin || port > r.PortMax) {
		return fail(ErrPortOutsideRange, "port %d is outside the relay's range %d-%d", port, r.PortMin, r.PortMax)
	}
	return nil
}

// CheckRequestedPort validates a public port an agent asked for against
// the relay's range and the token's policy.
func (r Rules) CheckRequestedPort(port int, policy auth.Policy) error {
	if port < r.PortMin || port > r.PortMax {
		return fail(ErrPortOutsideRange, "port %d is outside the relay's range %d-%d", port, r.PortMin, r.PortMax)
	}
	if lo, hi, ok := policy.PortRange(r.PortMin, r.PortMax); !ok || port < lo || port > hi {
		return fail(ErrPortNotAllowed, "the token's policy doesn't allow port %d (allowed: %s)", port, policy.Ports)
	}
	return nil
}

// AllocationRange is the range a port is allocated from for a token: the
// relay's range narrowed by the token's policy.
func (r Rules) AllocationRange(policy auth.Policy) (lo, hi int, err error) {
	lo, hi, ok := policy.PortRange(r.PortMin, r.PortMax)
	if !ok {
		return 0, 0, fail(ErrPortNotAllowed, "the token's port range %s doesn't overlap the relay's %d-%d", policy.Ports, r.PortMin, r.PortMax)
	}
	return lo, hi, nil
}

// Holder is the current holder of a name, as far as a claim cares.
type Holder struct {
	TokenID string
	AgentID string
	// Connected is true while an agent session serves the name; false
	// while it is parked (grace period or operator reservation).
	Connected bool
	// SameSession is true when the claim comes from the very session that
	// already serves the name (a duplicate registration).
	SameSession bool
}

// Decision is how a claim relates to the name's current holder.
type Decision int

const (
	// DecisionNew: nobody holds the name.
	DecisionNew Decision = iota + 1
	// DecisionReclaim: the token takes back its parked name.
	DecisionReclaim
	// DecisionTakeover: the same agent reconnected before its old session
	// was noticed dead; the new session replaces the old one.
	DecisionTakeover
)

// Decide applies the claim rules. holder is nil when nobody holds the
// name; active is the token's number of connected tunnels, not counting
// this name; maxTunnels 0 means no cap.
func Decide(holder *Holder, tokenID, agentID string, active, maxTunnels int) (Decision, error) {
	if holder != nil && holder.TokenID != tokenID {
		return 0, ErrNameTaken
	}
	if holder != nil && holder.Connected && (holder.AgentID != agentID || holder.SameSession) {
		return 0, ErrNameTaken
	}
	if maxTunnels > 0 && active >= maxTunnels {
		return 0, ErrMaxTunnels
	}
	switch {
	case holder == nil:
		return DecisionNew, nil
	case holder.Connected:
		return DecisionTakeover, nil
	}
	return DecisionReclaim, nil
}
