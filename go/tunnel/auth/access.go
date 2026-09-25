package auth

import (
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"net/netip"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

// Access is a tunnel's access policy, parsed and ready to check.
type Access struct {
	allow, deny []netip.Prefix
	users       map[string][]byte // username -> bcrypt hash
	tokenHash   []byte            // sha256 of the mode B access token
	oidc        *OIDCRule

	// verified caches digests of credentials that passed bcrypt, because
	// browsers resend basic auth on every request and bcrypt is slow by
	// design. Failed attempts are never cached.
	mu       sync.Mutex
	verified map[[sha256.Size]byte]time.Time // digest -> expiry
}

// basicCacheTTL is how long verified basic-auth credentials skip bcrypt.
const basicCacheTTL = 5 * time.Minute

// dummyHash keeps a lookup of an unknown basic-auth user as slow as a
// known one, so timing doesn't reveal which usernames exist.
var dummyHash, _ = bcrypt.GenerateFromPassword([]byte("l8tunnel"), bcrypt.DefaultCost)

// ParseAccess validates a tunnel's access policy. A nil policy allows
// everyone.
func ParseAccess(p *l8tunnel.AccessPolicy) (*Access, error) {
	a := &Access{users: map[string][]byte{}, verified: map[[sha256.Size]byte]time.Time{}}
	var err error
	if a.allow, err = ParsePrefixes(p.GetAllowIps()); err != nil {
		return nil, fmt.Errorf("allow_ips: %w", err)
	}
	if a.deny, err = ParsePrefixes(p.GetDenyIps()); err != nil {
		return nil, fmt.Errorf("deny_ips: %w", err)
	}
	for _, u := range p.GetBasicUsers() {
		if u.GetUsername() == "" || strings.Contains(u.GetUsername(), ":") {
			return nil, fmt.Errorf("basic auth username %q must be non-empty and contain no ':'", u.GetUsername())
		}
		if _, err := bcrypt.Cost([]byte(u.GetBcryptHash())); err != nil {
			return nil, fmt.Errorf("basic auth user %q: password hash is not a bcrypt hash", u.GetUsername())
		}
		if _, dup := a.users[u.GetUsername()]; dup {
			return nil, fmt.Errorf("duplicate basic auth user %q", u.GetUsername())
		}
		a.users[u.GetUsername()] = []byte(u.GetBcryptHash())
	}
	if o := p.GetOidc(); o != nil {
		rule, err := parseOIDC(o)
		if err != nil {
			return nil, err
		}
		a.oidc = rule
	}
	if h := p.GetAccessTokenSha256(); len(h) > 0 {
		if len(h) != sha256.Size {
			return nil, fmt.Errorf("access token hash must be %d bytes", sha256.Size)
		}
		a.tokenHash = h
	}
	return a, nil
}

// ParsePrefix accepts an address (1.2.3.4, ::1) or a CIDR (10.0.0.0/8).
func ParsePrefix(s string) (netip.Prefix, error) {
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return netip.Prefix{}, err
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(s)
	if err != nil {
		return netip.Prefix{}, err
	}
	addr = addr.Unmap()
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

// ParsePrefixes parses a list of addresses or CIDRs (see ParsePrefix).
func ParsePrefixes(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		p, err := ParsePrefix(s)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, nil
}

// AllowsIP applies the deny list, then the allow list (empty = everyone).
func (a *Access) AllowsIP(addr netip.Addr) bool {
	addr = addr.Unmap()
	for _, p := range a.deny {
		if p.Contains(addr) {
			return false
		}
	}
	if len(a.allow) == 0 {
		return true
	}
	for _, p := range a.allow {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// RequiresBasic reports whether HTTP basic auth is required.
func (a *Access) RequiresBasic() bool {
	return len(a.users) > 0
}

// CheckBasic verifies basic-auth credentials.
func (a *Access) CheckBasic(user, password string) bool {
	digest := sha256.Sum256([]byte(user + "\x00" + password))
	now := time.Now()
	a.mu.Lock()
	expiry, cached := a.verified[digest]
	a.mu.Unlock()
	if cached && now.Before(expiry) {
		return true
	}
	hash, ok := a.users[user]
	if !ok {
		bcrypt.CompareHashAndPassword(dummyHash, []byte(password))
		return false
	}
	if bcrypt.CompareHashAndPassword(hash, []byte(password)) != nil {
		return false
	}
	a.mu.Lock()
	for d, exp := range a.verified {
		if now.After(exp) {
			delete(a.verified, d)
		}
	}
	a.verified[digest] = now.Add(basicCacheTTL)
	a.mu.Unlock()
	return true
}

// RequiresToken reports whether mode B clients must present an access
// token.
func (a *Access) RequiresToken() bool {
	return len(a.tokenHash) > 0
}

// CheckToken verifies a presented access token in constant time.
func (a *Access) CheckToken(token string) bool {
	h := sha256.Sum256([]byte(token))
	return subtle.ConstantTimeCompare(h[:], a.tokenHash) == 1
}

// HashAccessToken is what an agent sends the relay for an access token.
func HashAccessToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// HashPassword returns a bcrypt hash for a basic-auth password.
func HashPassword(password string) (string, error) {
	if password == "" {
		return "", fmt.Errorf("password must not be empty")
	}
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	return string(h), err
}

// ValidateSpecAccess parses a tunnel's access policy and checks that it
// fits the tunnel type: basic auth only on http tunnels, access tokens
// only on tcp/ssh tunnels without a public port (raw TCP can't carry a
// token), and public ports only on tcp/ssh tunnels.
func ValidateSpecAccess(typ l8tunnel.TunnelType, publicPort uint32, p *l8tunnel.AccessPolicy) (*Access, error) {
	tcpLike := typ == l8tunnel.TunnelType_TUNNEL_TYPE_TCP || typ == l8tunnel.TunnelType_TUNNEL_TYPE_SSH
	if !tcpLike && publicPort != 0 {
		return nil, fmt.Errorf("public_port applies only to tcp and ssh tunnels")
	}
	a, err := ParseAccess(p)
	if err != nil {
		return nil, err
	}
	if a.RequiresBasic() && typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
		return nil, fmt.Errorf("basic auth applies only to http tunnels")
	}
	if a.oidc != nil && typ != l8tunnel.TunnelType_TUNNEL_TYPE_HTTP {
		return nil, fmt.Errorf("oidc applies only to http tunnels")
	}
	if a.oidc != nil && a.RequiresBasic() {
		return nil, fmt.Errorf("use either basic_auth or oidc, not both")
	}
	if a.RequiresToken() {
		if !tcpLike {
			return nil, fmt.Errorf("access tokens apply only to tcp and ssh tunnels")
		}
		if publicPort != 0 {
			return nil, fmt.Errorf("a tunnel with an access token has no public port: raw TCP can't carry the token")
		}
	}
	return a, nil
}

// OIDCRule is a tunnel's OIDC login requirement.
type OIDCRule struct {
	Provider string
	Emails   map[string]bool // lowercase
	Domains  map[string]bool // lowercase, without "@"
}

func parseOIDC(p *l8tunnel.OIDCPolicy) (*OIDCRule, error) {
	r := &OIDCRule{Provider: p.GetProvider(), Emails: map[string]bool{}, Domains: map[string]bool{}}
	if r.Provider == "" {
		return nil, fmt.Errorf("oidc.provider is required")
	}
	for _, e := range p.GetAllowEmails() {
		e = strings.ToLower(strings.TrimSpace(e))
		if !strings.Contains(e, "@") {
			return nil, fmt.Errorf("oidc allow_emails entry %q is not an email address", e)
		}
		r.Emails[e] = true
	}
	for _, d := range p.GetAllowDomains() {
		d = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(d), "@"))
		if d == "" || strings.Contains(d, "@") {
			return nil, fmt.Errorf("oidc allow_domains entry %q is not a domain", d)
		}
		r.Domains[d] = true
	}
	// Without an allow list, anyone with an account at the provider (any
	// Google account, say) could pass.
	if len(r.Emails) == 0 && len(r.Domains) == 0 {
		return nil, fmt.Errorf("oidc needs allow_emails or allow_domains")
	}
	return r, nil
}

// Allows reports whether a verified email may pass.
func (r *OIDCRule) Allows(email string) bool {
	email = strings.ToLower(email)
	if r.Emails[email] {
		return true
	}
	at := strings.LastIndex(email, "@")
	return at >= 0 && r.Domains[email[at+1:]]
}

// OIDC is the tunnel's OIDC rule, or nil.
func (a *Access) OIDC() *OIDCRule {
	return a.oidc
}
