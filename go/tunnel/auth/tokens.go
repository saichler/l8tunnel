// Package auth authenticates agents.
package auth

import (
	"bufio"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"os"
	"strings"
)

// MinTokenLength rejects tokens too short to resist guessing.
const MinTokenLength = 16

type tokenEntry struct {
	name string
	hash [sha256.Size]byte
}

// Tokens is the set of agent tokens the relay accepts. Only SHA-256
// hashes are kept in memory.
type Tokens struct {
	entries []tokenEntry
}

// NewTokens builds a token set from name -> token pairs.
func NewTokens(tokens map[string]string) (*Tokens, error) {
	if len(tokens) == 0 {
		return nil, fmt.Errorf("at least one agent token is required")
	}
	t := &Tokens{}
	for name, token := range tokens {
		if err := t.add(name, token); err != nil {
			return nil, err
		}
	}
	return t, nil
}

// LoadTokensFile reads a tokens file with one "<name> <token>" pair per
// line. Blank lines and lines starting with '#' are ignored.
func LoadTokensFile(path string) (*Tokens, error) {
	if path == "" {
		return nil, fmt.Errorf("a tokens file is required")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open tokens file: %w", err)
	}
	defer f.Close()

	tokens := map[string]string{}
	scanner := bufio.NewScanner(f)
	for lineNo := 1; scanner.Scan(); lineNo++ {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			return nil, fmt.Errorf("%s:%d: expected \"<name> <token>\"", path, lineNo)
		}
		if _, dup := tokens[fields[0]]; dup {
			return nil, fmt.Errorf("%s:%d: duplicate token name %q", path, lineNo, fields[0])
		}
		tokens[fields[0]] = fields[1]
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read tokens file: %w", err)
	}
	return NewTokens(tokens)
}

func (t *Tokens) add(name, token string) error {
	if name == "" {
		return fmt.Errorf("token name must not be empty")
	}
	if len(token) < MinTokenLength {
		return fmt.Errorf("token %q is shorter than %d characters", name, MinTokenLength)
	}
	t.entries = append(t.entries, tokenEntry{name: name, hash: sha256.Sum256([]byte(token))})
	return nil
}

// Verify returns the name of the matching token. Every entry is compared
// in constant time so timing doesn't reveal which token is close.
func (t *Tokens) Verify(token string) (string, bool) {
	hash := sha256.Sum256([]byte(token))
	match := ""
	found := false
	for _, e := range t.entries {
		if subtle.ConstantTimeCompare(hash[:], e.hash[:]) == 1 {
			match = e.name
			found = true
		}
	}
	return match, found
}
