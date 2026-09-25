// Package auth holds agent tokens and their policies, per-tunnel access
// rules, and per-IP rate limiting.
package auth

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"regexp"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Tokens look like l8t_<id>_<secret>: the ID (8 hex characters) finds the
// record, and only a bcrypt hash of the secret is stored.
const tokenPrefix = "l8t_"

var tokenPattern = regexp.MustCompile(`^l8t_([0-9a-f]{8})_([A-Za-z0-9_-]{43})$`)

// TokenRecord is a stored agent token.
type TokenRecord struct {
	ID      string    `json:"id"`
	Name    string    `json:"name"`
	Hash    []byte    `json:"hash"` // bcrypt of the secret part
	Created time.Time `json:"created"`
	Policy  Policy    `json:"policy"`
}

var namePattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

// NewToken creates a token and the record to store for it. The plaintext
// is shown to the operator once and never stored.
func NewToken(name string, policy Policy) (string, *TokenRecord, error) {
	idBytes := make([]byte, 4)
	secret := make([]byte, 32)
	rand.Read(idBytes)
	rand.Read(secret)
	token := tokenPrefix + hex.EncodeToString(idBytes) + "_" + base64.RawURLEncoding.EncodeToString(secret)
	rec, err := NewTokenRecord(name, token, policy, bcrypt.DefaultCost)
	if err != nil {
		return "", nil, err
	}
	return token, rec, nil
}

// NewTokenRecord builds the record for an existing plaintext token, hashing
// its secret with the given bcrypt cost.
func NewTokenRecord(name, token string, policy Policy, cost int) (*TokenRecord, error) {
	if !namePattern.MatchString(name) {
		return nil, fmt.Errorf("token name %q must be 1-64 letters, digits, '.', '_' or '-'", name)
	}
	if err := policy.Validate(); err != nil {
		return nil, err
	}
	id, secret, err := ParseToken(token)
	if err != nil {
		return nil, err
	}
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), cost)
	if err != nil {
		return nil, fmt.Errorf("hash token: %w", err)
	}
	return &TokenRecord{ID: id, Name: name, Hash: hash, Created: time.Now().UTC(), Policy: policy}, nil
}

// ParseToken splits a token into its ID and secret.
func ParseToken(token string) (id, secret string, err error) {
	m := tokenPattern.FindStringSubmatch(token)
	if m == nil {
		return "", "", fmt.Errorf("malformed token (want l8t_<id>_<secret>)")
	}
	return m[1], m[2], nil
}

// Verify reports whether secret matches the record, in constant time.
func (r *TokenRecord) Verify(secret string) bool {
	return bcrypt.CompareHashAndPassword(r.Hash, []byte(secret)) == nil
}
