package admin

import (
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/tunnel/store"
)

// TokenInfo describes a token without its secret.
type TokenInfo struct {
	ID      string      `json:"id"`
	Name    string      `json:"name"`
	Created time.Time   `json:"created"`
	Policy  auth.Policy `json:"policy"`
	Certs   int         `json:"certs"` // agent certificates issued
}

// IssueCertRequest is the body of POST /tokens/{name}/certs.
type IssueCertRequest struct {
	Days int `json:"days"`
}

// IssueCertResponse carries a new agent certificate and its only key copy.
type IssueCertResponse struct {
	Cert    string    `json:"cert"`
	Key     string    `json:"key"`
	Serial  string    `json:"serial"`
	Expires time.Time `json:"expires"`
}

// CreateTokenRequest is the body of POST /tokens.
type CreateTokenRequest struct {
	Name   string      `json:"name"`
	Policy auth.Policy `json:"policy"`
}

// CreateTokenResponse carries the new token; it is shown only once.
type CreateTokenResponse struct {
	TokenInfo
	Token string `json:"token"`
}

// RevokeTokenResponse reports how many agents were disconnected.
type RevokeTokenResponse struct {
	Disconnected int `json:"disconnected"`
}

// ReservationRequest is the body of POST /reservations.
type ReservationRequest struct {
	Name  string `json:"name"`
	Token string `json:"token"` // token name
	Port  int    `json:"port,omitempty"`
}

// ReservationInfo describes a permanent reservation.
type ReservationInfo struct {
	Name    string    `json:"name"`
	Token   string    `json:"token"`
	Port    int       `json:"port,omitempty"`
	Created time.Time `json:"created"`
}

// RelayHandler serves the relay's admin API. Store changes are applied to
// the running relay: a revoked token's agents are disconnected at once.
func RelayHandler(srv *relay.Server, st *store.Store, logger *slog.Logger) http.Handler {
	a := &relayAPI{srv: srv, st: st, log: logger}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", a.status)
	mux.HandleFunc("GET /tokens", a.listTokens)
	mux.HandleFunc("POST /tokens", a.createToken)
	mux.HandleFunc("DELETE /tokens/{name}", a.revokeToken)
	mux.HandleFunc("POST /tokens/{name}/certs", a.issueCert)
	mux.HandleFunc("GET /gateway-keys", a.listGatewayKeys)
	mux.HandleFunc("POST /gateway-keys", a.addGatewayKey)
	mux.HandleFunc("DELETE /gateway-keys/{name}", a.removeGatewayKey)
	mux.HandleFunc("GET /reservations", a.listReservations)
	mux.HandleFunc("POST /reservations", a.addReservation)
	mux.HandleFunc("DELETE /reservations/{name}", a.removeReservation)
	return mux
}

type relayAPI struct {
	srv *relay.Server
	st  *store.Store
	log *slog.Logger
}

func (a *relayAPI) status(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, a.srv.Status())
}

func (a *relayAPI) listTokens(w http.ResponseWriter, _ *http.Request) {
	tokens, err := a.st.Tokens()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]TokenInfo, 0, len(tokens))
	for _, t := range tokens {
		out = append(out, tokenInfo(t))
	}
	writeJSON(w, http.StatusOK, out)
}

func tokenInfo(t *auth.TokenRecord) TokenInfo {
	return TokenInfo{ID: t.ID, Name: t.Name, Created: t.Created, Policy: t.Policy, Certs: len(t.CertSerials)}
}

func (a *relayAPI) issueCert(w http.ResponseWriter, r *http.Request) {
	var req IssueCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return
	}
	issued, rec, err := a.st.IssueCert(r.PathValue("name"), req.Days)
	if err != nil {
		status := statusFor(err)
		if status == http.StatusInternalServerError && !errors.Is(err, store.ErrNotFound) {
			status = http.StatusBadRequest
		}
		writeErr(w, status, err)
		return
	}
	a.log.Info("agent certificate issued", "token", rec.Name, "serial", issued.Serial, "expires", issued.Expires)
	writeJSON(w, http.StatusCreated, IssueCertResponse{
		Cert: string(issued.CertPEM), Key: string(issued.KeyPEM), Serial: issued.Serial, Expires: issued.Expires,
	})
}

func (a *relayAPI) createToken(w http.ResponseWriter, r *http.Request) {
	var req CreateTokenRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return
	}
	token, rec, err := auth.NewToken(req.Name, req.Policy)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.st.AddToken(rec); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	a.log.Info("token created", "name", rec.Name, "id", rec.ID)
	writeJSON(w, http.StatusCreated, CreateTokenResponse{TokenInfo: tokenInfo(rec), Token: token})
}

func (a *relayAPI) revokeToken(w http.ResponseWriter, r *http.Request) {
	rec, err := a.st.TokenByName(r.PathValue("name"))
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	// Delete first, so the agents can't reconnect with it.
	if err := a.st.DeleteToken(rec.ID); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	n := a.srv.DisconnectToken(rec.ID)
	a.log.Info("token revoked", "name", rec.Name, "id", rec.ID, "disconnected", n)
	writeJSON(w, http.StatusOK, RevokeTokenResponse{Disconnected: n})
}

func (a *relayAPI) listReservations(w http.ResponseWriter, _ *http.Request) {
	list, err := a.st.Reservations()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	names, err := a.tokenNames()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	out := make([]ReservationInfo, 0, len(list))
	for _, res := range list {
		out = append(out, ReservationInfo{Name: res.Name, Token: names[res.TokenID], Port: res.Port, Created: res.Created})
	}
	writeJSON(w, http.StatusOK, out)
}

func (a *relayAPI) tokenNames() (map[string]string, error) {
	tokens, err := a.st.Tokens()
	if err != nil {
		return nil, err
	}
	names := map[string]string{}
	for _, t := range tokens {
		names[t.ID] = t.Name
	}
	return names, nil
}

func (a *relayAPI) addReservation(w http.ResponseWriter, r *http.Request) {
	var req ReservationRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return
	}
	rec, err := a.st.TokenByName(req.Token)
	if err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	// The relay validates the name and port and checks for conflicts;
	// only then is the reservation stored.
	if err := a.srv.Reserve(req.Name, rec.ID, req.Port); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	res := &store.Reservation{Name: req.Name, TokenID: rec.ID, Port: req.Port, Created: time.Now().UTC()}
	if err := a.st.PutReservation(res); err != nil {
		a.srv.Unreserve(req.Name)
		writeErr(w, statusFor(err), err)
		return
	}
	a.log.Info("name reserved", "name", req.Name, "token", rec.Name, "port", req.Port)
	writeJSON(w, http.StatusCreated, ReservationInfo{Name: res.Name, Token: rec.Name, Port: res.Port, Created: res.Created})
}

func (a *relayAPI) removeReservation(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.st.DeleteReservation(name); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	a.srv.Unreserve(name)
	a.log.Info("reservation removed", "name", name)
	w.WriteHeader(http.StatusNoContent)
}

func statusFor(err error) int {
	if errors.Is(err, store.ErrNotFound) {
		return http.StatusNotFound
	}
	return http.StatusInternalServerError
}

// AgentHandler serves the agent's status API.
func AgentHandler(a *agent.Agent) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /status", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, a.Status())
	})
	return mux
}

// GatewayKeyRequest is the body of POST /gateway-keys.
type GatewayKeyRequest struct {
	Name      string   `json:"name"`
	PublicKey string   `json:"public_key"`
	Tunnels   []string `json:"tunnels"`
}

func (a *relayAPI) listGatewayKeys(w http.ResponseWriter, _ *http.Request) {
	keys, err := a.st.GatewayKeys()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	if keys == nil {
		keys = []*auth.GatewayKey{}
	}
	writeJSON(w, http.StatusOK, keys)
}

func (a *relayAPI) addGatewayKey(w http.ResponseWriter, r *http.Request) {
	var req GatewayKeyRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, http.StatusBadRequest, fmt.Errorf("invalid request: %w", err))
		return
	}
	key, err := auth.NewGatewayKey(req.Name, req.PublicKey, req.Tunnels)
	if err != nil {
		writeErr(w, http.StatusBadRequest, err)
		return
	}
	if err := a.st.AddGatewayKey(key); err != nil {
		writeErr(w, http.StatusConflict, err)
		return
	}
	a.log.Info("gateway key added", "name", key.Name, "fingerprint", key.Fingerprint, "tunnels", key.Tunnels)
	writeJSON(w, http.StatusCreated, key)
}

func (a *relayAPI) removeGatewayKey(w http.ResponseWriter, r *http.Request) {
	name := r.PathValue("name")
	if err := a.st.DeleteGatewayKey(name); err != nil {
		writeErr(w, statusFor(err), err)
		return
	}
	a.log.Info("gateway key removed", "name", name)
	w.WriteHeader(http.StatusNoContent)
}
