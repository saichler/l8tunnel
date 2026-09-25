// Package edgeconf holds the rules for the edge's configuration: parsing a
// port forward's load-balancing targets, validating edge domains and their
// port forwards against each other, and checking uploaded certificates.
// The management backend validates with it before storing a domain, and
// the edge applies the same parsing when it builds its pools.
package edgeconf

import (
	"fmt"
	"net"
	"strconv"
	"strings"
)

// MaxWeight bounds a target's weight.
const MaxWeight = 100

// Target is one member of a port forward's pool, written as "host:port",
// "host:port*weight", or with a leading "!" when disabled.
type Target struct {
	Host     string
	Port     int
	Weight   int // 1 when not given
	Disabled bool
}

// ParseTarget parses one targets entry.
func ParseTarget(s string) (Target, error) {
	var t Target
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "!") {
		t.Disabled = true
		s = strings.TrimSpace(s[1:])
	}
	t.Weight = 1
	if hp, w, found := strings.Cut(s, "*"); found {
		weight, err := strconv.Atoi(strings.TrimSpace(w))
		if err != nil || weight < 1 || weight > MaxWeight {
			return Target{}, fmt.Errorf("target %q: the weight after * must be 1-%d", s, MaxWeight)
		}
		t.Weight = weight
		s = strings.TrimSpace(hp)
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil {
		return Target{}, fmt.Errorf("target %q must be host:port", s)
	}
	p, err := strconv.Atoi(port)
	if err != nil || p < 1 || p > 65535 {
		return Target{}, fmt.Errorf("target %q: invalid port", s)
	}
	if host == "" || strings.ContainsAny(host, " /") {
		return Target{}, fmt.Errorf("target %q: invalid host", s)
	}
	t.Host, t.Port = host, p
	return t, nil
}

// Address is host:port.
func (t Target) Address() string {
	return net.JoinHostPort(t.Host, strconv.Itoa(t.Port))
}

// String writes the target back in its entry form.
func (t Target) String() string {
	s := t.Address()
	if t.Weight > 1 {
		s += "*" + strconv.Itoa(t.Weight)
	}
	if t.Disabled {
		s = "!" + s
	}
	return s
}

// ParseTargets parses every entry, failing on the first bad one.
func ParseTargets(entries []string) ([]Target, error) {
	out := make([]Target, 0, len(entries))
	for _, e := range entries {
		t, err := ParseTarget(e)
		if err != nil {
			return nil, err
		}
		out = append(out, t)
	}
	return out, nil
}
