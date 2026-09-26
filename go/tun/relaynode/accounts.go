// Package relaynode runs a relay in the Kubernetes cluster: it links the
// relay (tunnel/relay) to the registry's claims engine, feeds it tokens,
// certificates and gateway keys from the management plane, and carries out
// the commands pushed to its TunRlyCtl listener.
package relaynode

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tun/access/agentcerts"
	"github.com/saichler/l8tunnel/go/tun/access/gwkeys"
	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8types/go/ifs"
)

// accounts is the relay's copy of the agent credentials: the relay checks
// every agent against it, so agents keep connecting while the management
// backend is down. A snapshot on disk survives restarts.
type accounts struct {
	mu       sync.RWMutex
	downAt   time.Time // last failed live lookup
	tokens   map[string]*auth.TokenRecord // by token ID
	keys     map[string]*auth.GatewayKey  // by fingerprint
	snapshot string
	vnic     ifs.IVNic
}

type accountsSnapshot struct {
	Tokens []*auth.TokenRecord `json:"tokens"`
	Keys   []*auth.GatewayKey  `json:"keys"`
}

func newAccounts(vnic ifs.IVNic, snapshot string) *accounts {
	return &accounts{tokens: map[string]*auth.TokenRecord{}, keys: map[string]*auth.GatewayKey{}, snapshot: snapshot, vnic: vnic}
}

// liveLookupBackoff: after a failed live lookup, the cache answers alone
// for this long, so agent handshakes don't wait on a down backend.
const liveLookupBackoff = 30 * time.Second

// TokenByID implements relay.TokenStore. Agent handshakes are rare, so the
// token and its certificate serials are looked up live: a token issued a
// moment ago works at once, and a revoked one is refused at once. While the
// backend is unreachable the cache answers.
func (a *accounts) TokenByID(id string) (*auth.TokenRecord, error) {
	a.mu.RLock()
	down := time.Since(a.downAt) < liveLookupBackoff
	a.mu.RUnlock()
	if !down {
		rec, err := a.fetchToken(id)
		if err == nil {
			a.mu.Lock()
			if rec == nil {
				delete(a.tokens, id)
			} else {
				a.tokens[id] = rec
			}
			a.mu.Unlock()
			return copyRecord(rec), nil
		}
		a.mu.Lock()
		a.downAt = time.Now()
		a.mu.Unlock()
		a.vnic.Resources().Logger().Warning("live token lookup failed; using the cache: ", err.Error())
	}
	a.mu.RLock()
	defer a.mu.RUnlock()
	return copyRecord(a.tokens[id]), nil
}

// fetchToken reads one token and its valid certificate serials.
func (a *accounts) fetchToken(id string) (*auth.TokenRecord, error) {
	t, err := tokens.Token(id, a.vnic)
	if err != nil || t == nil {
		return nil, err
	}
	certs, err := agentcerts.Certs(a.vnic)
	if err != nil {
		return nil, err
	}
	return common.TokenRecord(t, agentcerts.ValidSerials(id, certs))
}

func copyRecord(rec *auth.TokenRecord) *auth.TokenRecord {
	if rec == nil {
		return nil
	}
	cp := *rec
	return &cp
}

// GatewayKeyByFingerprint implements relay.GatewayKeyStore.
func (a *accounts) GatewayKeyByFingerprint(fp string) (*auth.GatewayKey, error) {
	a.mu.RLock()
	defer a.mu.RUnlock()
	return a.keys[fp], nil
}

// dropToken forgets a revoked token at once.
func (a *accounts) dropToken(id string) {
	a.mu.Lock()
	defer a.mu.Unlock()
	delete(a.tokens, id)
}

// refresh reloads everything from the management backend and saves a
// snapshot; on error the current copy stays.
func (a *accounts) refresh() error {
	toks, err := tokens.Tokens(a.vnic)
	if err != nil {
		return err
	}
	certs, err := agentcerts.Certs(a.vnic)
	if err != nil {
		return err
	}
	keys, err := gwkeys.Keys(a.vnic)
	if err != nil {
		return err
	}
	byID := map[string]*auth.TokenRecord{}
	for _, t := range toks {
		rec, err := common.TokenRecord(t, agentcerts.ValidSerials(t.TokenId, certs))
		if err != nil {
			a.vnic.Resources().Logger().Warning("skipping token ", t.Name, ": ", err.Error())
			continue
		}
		byID[rec.ID] = rec
	}
	byFP := map[string]*auth.GatewayKey{}
	for _, k := range keys {
		byFP[k.Fingerprint] = &auth.GatewayKey{Name: k.Name, PublicKey: k.PublicKey, Fingerprint: k.Fingerprint, Tunnels: k.Tunnels}
	}
	a.mu.Lock()
	a.tokens, a.keys = byID, byFP
	a.mu.Unlock()
	return a.save()
}

func (a *accounts) save() error {
	a.mu.RLock()
	snap := accountsSnapshot{}
	for _, t := range a.tokens {
		snap.Tokens = append(snap.Tokens, t)
	}
	for _, k := range a.keys {
		snap.Keys = append(snap.Keys, k)
	}
	a.mu.RUnlock()
	data, err := json.Marshal(snap)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.snapshot), 0o700); err != nil {
		return err
	}
	tmp := a.snapshot + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, a.snapshot)
}

// load reads the snapshot, for starting while the backend is unreachable.
func (a *accounts) load() error {
	data, err := os.ReadFile(a.snapshot)
	if err != nil {
		return err
	}
	snap := accountsSnapshot{}
	if err := json.Unmarshal(data, &snap); err != nil {
		return err
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	for _, t := range snap.Tokens {
		a.tokens[t.ID] = t
	}
	for _, k := range snap.Keys {
		a.keys[k.Fingerprint] = k
	}
	return nil
}
