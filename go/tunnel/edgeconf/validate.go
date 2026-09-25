package edgeconf

import (
	"fmt"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// NormalizeName lowercases a domain or alias and checks it: a host name
// with at least two labels, or a wildcard "*.<host name>".
func NormalizeName(s string) (string, error) {
	if rest, ok := strings.CutPrefix(strings.TrimSpace(s), "*."); ok {
		d, err := protocol.NormalizeDomain(rest)
		if err != nil {
			return "", err
		}
		return "*." + d, nil
	}
	return protocol.NormalizeDomain(strings.TrimSpace(s))
}

// Names are a domain's domain followed by its aliases.
func Names(d *tun.EdgeDomain) []string {
	return append([]string{d.Domain}, d.Aliases...)
}

// ValidateDomain checks one domain on its own and against the others
// (every other stored domain; a row with the same domain_id is skipped, so
// others may include the domain's previous version). It normalizes the
// domain and alias names in place.
func ValidateDomain(d *tun.EdgeDomain, others []*tun.EdgeDomain, baseDomain string) error {
	if err := NormalizeNames(d); err != nil {
		return err
	}
	switch d.Kind {
	case tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE:
	case tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE:
		if d.Domain != baseDomain {
			return fmt.Errorf("the tunnel base domain must be %s", baseDomain)
		}
	default:
		return fmt.Errorf("domain %s: kind is required", d.Domain)
	}
	if err := checkIPLists(d); err != nil {
		return err
	}
	seen := map[string]bool{}
	for _, n := range Names(d) {
		if seen[n] {
			return fmt.Errorf("%s is listed twice", n)
		}
		seen[n] = true
	}
	for _, o := range others {
		if o.DomainId == d.DomainId {
			continue
		}
		if d.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE && o.Kind == d.Kind {
			return fmt.Errorf("there is already a tunnel base domain (%s)", o.Domain)
		}
		for _, n := range Names(o) {
			if seen[strings.ToLower(n)] {
				return fmt.Errorf("%s already belongs to domain %s", n, o.Domain)
			}
		}
	}
	for i, pf := range d.PortForwards {
		if err := checkForward(d, pf); err != nil {
			return fmt.Errorf("port forward %d (%s): %w", i+1, portLabel(pf), err)
		}
	}
	return checkPortConflicts(d, others)
}

// NormalizeNames lowercases and checks the domain and alias names in place.
func NormalizeNames(d *tun.EdgeDomain) error {
	if strings.HasPrefix(strings.TrimSpace(d.Domain), "*.") {
		return fmt.Errorf("the domain itself can't be a wildcard; add *.%s as an alias", strings.TrimPrefix(d.Domain, "*."))
	}
	n, err := NormalizeName(d.Domain)
	if err != nil {
		return err
	}
	d.Domain = n
	for i, a := range d.Aliases {
		if d.Aliases[i], err = NormalizeName(a); err != nil {
			return err
		}
	}
	return nil
}

func checkIPLists(d *tun.EdgeDomain) error {
	for _, list := range [][]string{d.AllowIps, d.DenyIps} {
		for _, v := range list {
			if _, err := auth.ParsePrefix(v); err != nil {
				return fmt.Errorf("IP list entry %q: %w", v, err)
			}
		}
	}
	return nil
}

func portLabel(pf *tun.EdgePortForward) string {
	if pf.ListenPortEnd > 0 {
		return fmt.Sprintf("ports %d-%d", pf.ListenPort, pf.ListenPortEnd)
	}
	return fmt.Sprintf("port %d", pf.ListenPort)
}

func checkForward(d *tun.EdgeDomain, pf *tun.EdgePortForward) error {
	if pf.ListenPort < 1 || pf.ListenPort > 65535 {
		return fmt.Errorf("the listen port must be 1-65535")
	}
	if pf.ListenPortEnd != 0 && (pf.ListenPortEnd <= pf.ListenPort || pf.ListenPortEnd > 65535) {
		return fmt.Errorf("the range end must be above the listen port and at most 65535")
	}
	base := d.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE
	switch pf.Protocol {
	case tun.EdgeProtocol_EDGE_PROTOCOL_TLS, tun.EdgeProtocol_EDGE_PROTOCOL_HTTP, tun.EdgeProtocol_EDGE_PROTOCOL_TCP:
	default:
		return fmt.Errorf("the protocol is required")
	}
	switch pf.Mode {
	case tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE:
		if pf.Protocol != tun.EdgeProtocol_EDGE_PROTOCOL_TLS {
			return fmt.Errorf("terminate works only on TLS ports")
		}
		if d.CertStatus != tun.EdgeCertStatus_EDGE_CERT_STATUS_VALID && d.CertStatus != tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRING {
			return fmt.Errorf("terminate needs a valid certificate for %s; upload one first", d.Domain)
		}
	case tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH:
	case tun.EdgeForwardMode_EDGE_FORWARD_MODE_RELAY:
		if !base {
			return fmt.Errorf("only the tunnel base domain forwards to the relays")
		}
	default:
		return fmt.Errorf("the mode is required")
	}
	if pf.ListenPortEnd != 0 && pf.Protocol != tun.EdgeProtocol_EDGE_PROTOCOL_TCP {
		return fmt.Errorf("a port range must be TCP")
	}
	if err := checkTarget(pf, base); err != nil {
		return err
	}
	switch pf.HealthType {
	case tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTP, tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTPS:
		if !strings.HasPrefix(pf.HealthPath, "/") {
			return fmt.Errorf("an HTTP health check needs a path starting with /")
		}
	}
	if pf.HealthInterval < 0 || pf.HealthInterval > 3600 {
		return fmt.Errorf("the health interval must be 0-3600 seconds")
	}
	return nil
}

func checkTarget(pf *tun.EdgePortForward, base bool) error {
	switch pf.TargetKind {
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS:
		targets, err := ParseTargets(pf.Targets)
		if err != nil {
			return err
		}
		enabled := 0
		for _, t := range targets {
			if !t.Disabled {
				enabled++
			}
		}
		if enabled == 0 {
			return fmt.Errorf("at least one enabled target is required")
		}
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_DNS:
		if _, err := protocol.NormalizeDomain(pf.TargetDns); err != nil && !strings.Contains(pf.TargetDns, ".svc") {
			return fmt.Errorf("the DNS target: %w", err)
		}
		if pf.TargetPort < 1 || pf.TargetPort > 65535 {
			return fmt.Errorf("the target port must be 1-65535")
		}
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL:
		if pf.TargetPort < 1 || pf.TargetPort > 65535 {
			return fmt.Errorf("the target port must be 1-65535")
		}
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS:
		if !base {
			return fmt.Errorf("only the tunnel base domain targets the relays")
		}
	default:
		return fmt.Errorf("the target kind is required")
	}
	return nil
}

// checkPortConflicts: a TCP port (or range) belongs to one domain; a port
// can't mix protocols; a domain can't list the same port twice.
func checkPortConflicts(d *tun.EdgeDomain, others []*tun.EdgeDomain) error {
	for i, a := range d.PortForwards {
		for _, b := range d.PortForwards[i+1:] {
			if overlap(a, b) {
				return fmt.Errorf("%s and %s overlap in %s", portLabel(a), portLabel(b), d.Domain)
			}
		}
	}
	for _, o := range others {
		if o.DomainId == d.DomainId {
			continue
		}
		for _, a := range d.PortForwards {
			for _, b := range o.PortForwards {
				if !overlap(a, b) {
					continue
				}
				switch {
				case a.Protocol != b.Protocol:
					return fmt.Errorf("%s is %s on domain %s", portLabel(b), protocolName(b.Protocol), o.Domain)
				case a.Protocol == tun.EdgeProtocol_EDGE_PROTOCOL_TCP:
					return fmt.Errorf("%s is TCP on domain %s; a TCP port can't be shared", portLabel(b), o.Domain)
				}
			}
		}
	}
	return nil
}

func overlap(a, b *tun.EdgePortForward) bool {
	aEnd, bEnd := a.ListenPortEnd, b.ListenPortEnd
	if aEnd == 0 {
		aEnd = a.ListenPort
	}
	if bEnd == 0 {
		bEnd = b.ListenPort
	}
	return a.ListenPort <= bEnd && b.ListenPort <= aEnd
}

func protocolName(p tun.EdgeProtocol) string {
	return strings.TrimPrefix(p.String(), "EDGE_PROTOCOL_")
}
