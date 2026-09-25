// Package store persists the relay's agent tokens and permanent name
// reservations in an embedded bbolt database.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"time"

	bolt "go.etcd.io/bbolt"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

var (
	bucketTokens       = []byte("tokens")       // token ID -> TokenRecord
	bucketReservations = []byte("reservations") // tunnel name -> Reservation
)

// ErrNotFound is returned when a token or reservation doesn't exist.
var ErrNotFound = errors.New("not found")

// Reservation permanently binds a tunnel name (and, for tcp/ssh, a public
// port) to a token.
type Reservation struct {
	Name    string    `json:"name"`
	TokenID string    `json:"token_id"`
	Port    int       `json:"port,omitempty"`
	Created time.Time `json:"created"`
}

// Store is the relay's database.
type Store struct {
	db *bolt.DB
}

// Open opens (creating if needed) the database at path. Only one process
// can hold it; a second relay fails instead of waiting.
func Open(path string) (*Store, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("create storage directory: %w", err)
	}
	db, err := bolt.Open(path, 0o600, &bolt.Options{Timeout: time.Second})
	if err != nil {
		if errors.Is(err, bolt.ErrTimeout) {
			return nil, fmt.Errorf("open %s: the database is locked (is another l8tunnel-server running?)", path)
		}
		return nil, fmt.Errorf("open %s: %w", path, err)
	}
	err = db.Update(func(tx *bolt.Tx) error {
		for _, b := range [][]byte{bucketTokens, bucketReservations} {
			if _, err := tx.CreateBucketIfNotExists(b); err != nil {
				return err
			}
		}
		return nil
	})
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize %s: %w", path, err)
	}
	return &Store{db: db}, nil
}

// Close closes the database.
func (s *Store) Close() error {
	return s.db.Close()
}

// AddToken stores a new token. Token names are unique.
func (s *Store) AddToken(rec *auth.TokenRecord) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		if b.Get([]byte(rec.ID)) != nil {
			return fmt.Errorf("token ID %s already exists", rec.ID)
		}
		exists := false
		err := forEachToken(b, func(r *auth.TokenRecord) {
			if r.Name == rec.Name {
				exists = true
			}
		})
		if err != nil {
			return err
		}
		if exists {
			return fmt.Errorf("a token named %q already exists", rec.Name)
		}
		return put(b, rec.ID, rec)
	})
}

// TokenByID returns a token, or nil if there is none. It implements the
// relay's token lookup.
func (s *Store) TokenByID(id string) (*auth.TokenRecord, error) {
	var rec *auth.TokenRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		data := tx.Bucket(bucketTokens).Get([]byte(id))
		if data == nil {
			return nil
		}
		rec = &auth.TokenRecord{}
		return json.Unmarshal(data, rec)
	})
	return rec, err
}

// TokenByName returns a token by name, or ErrNotFound.
func (s *Store) TokenByName(name string) (*auth.TokenRecord, error) {
	tokens, err := s.Tokens()
	if err != nil {
		return nil, err
	}
	for _, t := range tokens {
		if t.Name == name {
			return t, nil
		}
	}
	return nil, fmt.Errorf("token %q: %w", name, ErrNotFound)
}

// Tokens lists all tokens sorted by name.
func (s *Store) Tokens() ([]*auth.TokenRecord, error) {
	var out []*auth.TokenRecord
	err := s.db.View(func(tx *bolt.Tx) error {
		return forEachToken(tx.Bucket(bucketTokens), func(r *auth.TokenRecord) { out = append(out, r) })
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// DeleteToken removes a token and its reservations.
func (s *Store) DeleteToken(id string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		tokens := tx.Bucket(bucketTokens)
		if tokens.Get([]byte(id)) == nil {
			return fmt.Errorf("token ID %s: %w", id, ErrNotFound)
		}
		if err := tokens.Delete([]byte(id)); err != nil {
			return err
		}
		res := tx.Bucket(bucketReservations)
		var names [][]byte
		err := res.ForEach(func(k, v []byte) error {
			r := &Reservation{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			if r.TokenID == id {
				names = append(names, append([]byte(nil), k...))
			}
			return nil
		})
		if err != nil {
			return err
		}
		for _, name := range names {
			if err := res.Delete(name); err != nil {
				return err
			}
		}
		return nil
	})
}

// PutReservation adds or replaces a reservation.
func (s *Store) PutReservation(r *Reservation) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		if tx.Bucket(bucketTokens).Get([]byte(r.TokenID)) == nil {
			return fmt.Errorf("token ID %s: %w", r.TokenID, ErrNotFound)
		}
		return put(tx.Bucket(bucketReservations), r.Name, r)
	})
}

// Reservations lists all reservations sorted by name.
func (s *Store) Reservations() ([]*Reservation, error) {
	var out []*Reservation
	err := s.db.View(func(tx *bolt.Tx) error {
		return tx.Bucket(bucketReservations).ForEach(func(_, v []byte) error {
			r := &Reservation{}
			if err := json.Unmarshal(v, r); err != nil {
				return err
			}
			out = append(out, r)
			return nil
		})
	})
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, err
}

// DeleteReservation removes a reservation.
func (s *Store) DeleteReservation(name string) error {
	return s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketReservations)
		if b.Get([]byte(name)) == nil {
			return fmt.Errorf("reservation %q: %w", name, ErrNotFound)
		}
		return b.Delete([]byte(name))
	})
}

func put(b *bolt.Bucket, key string, v interface{}) error {
	data, err := json.Marshal(v)
	if err != nil {
		return err
	}
	return b.Put([]byte(key), data)
}

func forEachToken(b *bolt.Bucket, fn func(*auth.TokenRecord)) error {
	return b.ForEach(func(_, v []byte) error {
		r := &auth.TokenRecord{}
		if err := json.Unmarshal(v, r); err != nil {
			return err
		}
		fn(r)
		return nil
	})
}

var bucketCA = []byte("ca") // "cert", "key" -> PEM of the agent CA

// AgentCA returns the relay's agent CA, creating and storing it on first
// use.
func (s *Store) AgentCA() (*auth.AgentCA, error) {
	var ca *auth.AgentCA
	err := s.db.Update(func(tx *bolt.Tx) error {
		b, err := tx.CreateBucketIfNotExists(bucketCA)
		if err != nil {
			return err
		}
		if certPEM, keyPEM := b.Get([]byte("cert")), b.Get([]byte("key")); certPEM != nil && keyPEM != nil {
			ca, err = auth.LoadAgentCA(certPEM, keyPEM)
			return err
		}
		if ca, err = auth.NewAgentCA(); err != nil {
			return err
		}
		certPEM, keyPEM, err := ca.PEM()
		if err != nil {
			return err
		}
		if err := b.Put([]byte("cert"), certPEM); err != nil {
			return err
		}
		return b.Put([]byte("key"), keyPEM)
	})
	return ca, err
}

// IssueCert issues an agent certificate for a token and records its serial.
func (s *Store) IssueCert(tokenName string, days int) (*auth.IssuedCert, *auth.TokenRecord, error) {
	ca, err := s.AgentCA()
	if err != nil {
		return nil, nil, err
	}
	var issued *auth.IssuedCert
	var rec *auth.TokenRecord
	err = s.db.Update(func(tx *bolt.Tx) error {
		b := tx.Bucket(bucketTokens)
		err := forEachToken(b, func(r *auth.TokenRecord) {
			if r.Name == tokenName {
				rec = r
			}
		})
		if err != nil {
			return err
		}
		if rec == nil {
			return fmt.Errorf("token %q: %w", tokenName, ErrNotFound)
		}
		if issued, err = ca.Issue(rec, days); err != nil {
			return err
		}
		rec.CertSerials = append(rec.CertSerials, issued.Serial)
		return put(b, rec.ID, rec)
	})
	return issued, rec, err
}
