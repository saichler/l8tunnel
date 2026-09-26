package certs

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"strings"
	"sync"
)

// Set holds one certificate per domain (the edge's TERMINATE sites),
// chosen by SNI: an exact name first, then a wildcard (*.example.com). A
// name no certificate covers fails the handshake: it never falls back to
// another domain's certificate.
type Set struct {
	mu    sync.RWMutex
	byKey map[string]*tls.Certificate // domain ID -> certificate
	names map[string]*tls.Certificate // served name -> certificate
}

// NewSet returns an empty set.
func NewSet() *Set {
	return &Set{byKey: map[string]*tls.Certificate{}, names: map[string]*tls.Certificate{}}
}

// Put stores key's certificate for names (replacing key's previous one).
func (s *Set) Put(key string, certPEM, keyPEM []byte, names []string) error {
	pair, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("certificate for %s: %w", key, err)
	}
	if pair.Leaf, err = x509.ParseCertificate(pair.Certificate[0]); err != nil {
		return fmt.Errorf("certificate for %s: %w", key, err)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
	s.byKey[key] = &pair
	for _, n := range names {
		s.names[strings.ToLower(n)] = &pair
	}
	return nil
}

// Remove drops key's certificate.
func (s *Set) Remove(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.removeLocked(key)
}

func (s *Set) removeLocked(key string) {
	old := s.byKey[key]
	if old == nil {
		return
	}
	delete(s.byKey, key)
	for n, c := range s.names {
		if c == old {
			delete(s.names, n)
		}
	}
}

// Keys lists the domains that have a certificate.
func (s *Set) Keys() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, 0, len(s.byKey))
	for k := range s.byKey {
		out = append(out, k)
	}
	return out
}

// GetCertificate implements tls.Config.GetCertificate.
func (s *Set) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	name := strings.ToLower(strings.TrimSuffix(hello.ServerName, "."))
	s.mu.RLock()
	defer s.mu.RUnlock()
	if c := s.names[name]; c != nil {
		return c, nil
	}
	if i := strings.IndexByte(name, '.'); i > 0 {
		if c := s.names["*"+name[i:]]; c != nil {
			return c, nil
		}
	}
	return nil, fmt.Errorf("no certificate for %q", name)
}
