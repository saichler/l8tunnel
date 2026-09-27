// Package edgeconf holds the rules for the edge's configuration: a port
// forward's load-balancing targets, validating edge domains and their port
// forwards against each other, and checking uploaded certificates. The
// management backend validates with it before storing a domain, and the
// edge reads targets the same way when it builds its pools.
package edgeconf

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// MaxWeight bounds a target's weight.
const MaxWeight = 100

// CheckTarget validates one target.
func CheckTarget(t *tun.EdgeTarget) error {
	if t == nil {
		return fmt.Errorf("a target is empty")
	}
	if t.Host == "" || strings.ContainsAny(t.Host, " /:") && net.ParseIP(t.Host) == nil {
		return fmt.Errorf("target %q: invalid host", t.Host)
	}
	if t.Port < 1 || t.Port > 65535 {
		return fmt.Errorf("target %s: the port must be 1-65535", t.Host)
	}
	if t.Weight < 0 || t.Weight > MaxWeight {
		return fmt.Errorf("target %s: the weight must be 1-%d", Address(t), MaxWeight)
	}
	return nil
}

// Weight is a target's weight: 0 (not set) means 1.
func Weight(t *tun.EdgeTarget) int {
	if t.Weight < 1 {
		return 1
	}
	return int(t.Weight)
}

// Address is a target's host:port.
func Address(t *tun.EdgeTarget) string {
	return net.JoinHostPort(t.Host, strconv.Itoa(int(t.Port)))
}
