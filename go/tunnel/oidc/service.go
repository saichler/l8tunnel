package oidc

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	gooidc "github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

const (
	// AuthPath is handled by the relay on every OIDC-protected tunnel host.
	AuthPath = "/.l8tunnel/auth"
	// UserHeader carries the verified email to the service.
	UserHeader = "X-L8tunnel-User"

	sessionCookie = "l8tunnel_session"
	flowCookieKey = "l8tunnel_oidc_flow"
	loginTTL      = 10 * time.Minute
	codeTTL       = time.Minute
)

// Service runs the login flow.
type Service struct {
	cfg    Config
	signer signer

	mu        sync.Mutex
	providers map[string]*gooidc.Provider // discovered lazily
	usedCodes map[string]int64            // login code ID -> expiry
	bind      Binding
}

// New validates cfg. Providers are discovered on first use, so a provider
// outage doesn't stop the relay from starting.
func New(cfg Config) (*Service, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return &Service{cfg: cfg, signer: signer{key: cfg.Key}, providers: map[string]*gooidc.Provider{},
		usedCodes: map[string]int64{}}, nil
}

// Bind connects the service to the relay.
func (s *Service) Bind(b Binding) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.bind = b
}

// AuthHost is the login host name.
func (s *Service) AuthHost() string { return s.cfg.AuthHost }

// HasProvider reports whether a provider is configured.
func (s *Service) HasProvider(name string) bool {
	_, ok := s.cfg.Providers[name]
	return ok
}

func (s *Service) binding() Binding {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bind
}

func (s *Service) page(w http.ResponseWriter, status int, code, message, host string) {
	s.cfg.ErrorPage(w, status, code, http.StatusText(status), message, host)
}

// Authorize enforces rule on a request to a tunnel host. It returns the
// verified email and true when the request may proceed; otherwise it has
// written the response (a redirect to log in, or an error page).
func (s *Service) Authorize(w http.ResponseWriter, r *http.Request, rule *auth.OIDCRule) (string, bool) {
	host := normalizeHost(r.Host)
	if r.URL.Path == AuthPath {
		s.finishLogin(w, r, rule, host)
		return "", false
	}
	if c, err := r.Cookie(sessionCookie); err == nil {
		var sess session
		if s.signer.verify(purposeSession, c.Value, &sess) == nil && !expired(sess.Exp) && sess.Host == host {
			if !rule.Allows(sess.Email) {
				s.page(w, http.StatusForbidden, "not-allowed", sess.Email+" may not use this tunnel.", r.Host)
				return "", false
			}
			stripCookie(r, sessionCookie)
			return sess.Email, true
		}
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		s.page(w, http.StatusUnauthorized, "login-required", "Sign in to use this tunnel.", r.Host)
		return "", false
	}
	state, err := s.signer.sign(purposeLogin, loginState{Host: r.Host, Path: r.URL.RequestURI(), Exp: time.Now().Add(loginTTL).Unix()})
	if err != nil {
		s.page(w, http.StatusInternalServerError, "login-error", "Could not start the login.", r.Host)
		return "", false
	}
	http.Redirect(w, r, s.authURL("/login?state="+url.QueryEscape(state)), http.StatusFound)
	return "", false
}

// finishLogin turns a login code from the auth host into a session cookie.
func (s *Service) finishLogin(w http.ResponseWriter, r *http.Request, rule *auth.OIDCRule, host string) {
	var code loginCode
	err := s.signer.verify(purposeCode, r.URL.Query().Get("code"), &code)
	if err != nil || expired(code.Exp) || normalizeHost(code.Host) != host || !s.useCode(code.ID, code.Exp) {
		s.page(w, http.StatusBadRequest, "login-invalid", "The login link is invalid or expired; try again.", r.Host)
		return
	}
	if !rule.Allows(code.Email) {
		s.page(w, http.StatusForbidden, "not-allowed", code.Email+" may not use this tunnel.", r.Host)
		return
	}
	value, err := s.signer.sign(purposeSession, session{Email: code.Email, Host: host, Exp: time.Now().Add(s.cfg.SessionTTL).Unix()})
	if err != nil {
		s.page(w, http.StatusInternalServerError, "login-error", "Could not create the session.", r.Host)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookie, Value: value, Path: "/", MaxAge: int(s.cfg.SessionTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	s.cfg.Logger.Info("oidc login", "host", host, "email", code.Email)
	http.Redirect(w, r, safePath(code.Path), http.StatusFound)
}

// useCode marks a login code as used; false if it already was.
func (s *Service) useCode(id string, exp int64) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now().Unix()
	for k, e := range s.usedCodes {
		if e < now {
			delete(s.usedCodes, k)
		}
	}
	if _, used := s.usedCodes[id]; used || id == "" {
		return false
	}
	s.usedCodes[id] = exp
	return true
}

// AuthHandler serves the auth host: /login starts the provider round trip,
// /callback finishes it.
func (s *Service) AuthHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /login", s.login)
	mux.HandleFunc("GET /callback", s.callback)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		s.page(w, http.StatusNotFound, "not-found", "This is the relay's login host.", r.Host)
	})
	return mux
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var st loginState
	if err := s.signer.verify(purposeLogin, r.URL.Query().Get("state"), &st); err != nil || expired(st.Exp) {
		s.page(w, http.StatusBadRequest, "login-invalid", "The login link is invalid or expired; try again.", r.Host)
		return
	}
	rule := s.ruleFor(st.Host)
	if rule == nil {
		s.page(w, http.StatusBadRequest, "login-invalid", "That host doesn't use this relay's login.", r.Host)
		return
	}
	oc, err := s.oauthConfig(r.Context(), rule.Provider)
	if err != nil {
		s.cfg.Logger.Warn("oidc provider unavailable", "provider", rule.Provider, "error", err)
		s.page(w, http.StatusBadGateway, "provider-unavailable", "The login provider can't be reached; try again shortly.", r.Host)
		return
	}
	flow := flowCookie{Nonce: randomString(18), Verifier: oauth2.GenerateVerifier(), Provider: rule.Provider,
		Login: st, Exp: time.Now().Add(loginTTL).Unix()}
	value, err := s.signer.sign(purposeFlow, flow)
	if err != nil {
		s.page(w, http.StatusInternalServerError, "login-error", "Could not start the login.", r.Host)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookieKey, Value: value, Path: "/", MaxAge: int(loginTTL.Seconds()),
		Secure: true, HttpOnly: true, SameSite: http.SameSiteLaxMode})
	http.Redirect(w, r, oc.AuthCodeURL(flow.Nonce, oauth2.S256ChallengeOption(flow.Verifier), gooidc.Nonce(flow.Nonce)), http.StatusFound)
}

func (s *Service) callback(w http.ResponseWriter, r *http.Request) {
	fail := func(status int, code, msg string, err error) {
		s.cfg.Logger.Warn("oidc callback failed", "reason", code, "error", err)
		s.page(w, status, code, msg, r.Host)
	}
	c, err := r.Cookie(flowCookieKey)
	var flow flowCookie
	if err != nil || s.signer.verify(purposeFlow, c.Value, &flow) != nil || expired(flow.Exp) {
		fail(http.StatusBadRequest, "login-invalid", "The login session is missing or expired; try again.", err)
		return
	}
	http.SetCookie(w, &http.Cookie{Name: flowCookieKey, Path: "/", MaxAge: -1, Secure: true, HttpOnly: true})
	if r.URL.Query().Get("state") != flow.Nonce {
		fail(http.StatusBadRequest, "login-invalid", "The login response doesn't match this browser.", nil)
		return
	}
	if e := r.URL.Query().Get("error"); e != "" {
		fail(http.StatusForbidden, "login-refused", "The login provider refused the login: "+e, nil)
		return
	}
	ctx := gooidc.ClientContext(r.Context(), s.cfg.HTTPClient)
	oc, err := s.oauthConfig(ctx, flow.Provider)
	if err != nil {
		fail(http.StatusBadGateway, "provider-unavailable", "The login provider can't be reached; try again shortly.", err)
		return
	}
	tok, err := oc.Exchange(ctx, r.URL.Query().Get("code"), oauth2.VerifierOption(flow.Verifier))
	if err != nil {
		fail(http.StatusBadGateway, "login-failed", "The login provider rejected the code exchange.", err)
		return
	}
	raw, _ := tok.Extra("id_token").(string)
	provider, _ := s.provider(ctx, flow.Provider)
	idToken, err := provider.Verifier(&gooidc.Config{ClientID: s.cfg.Providers[flow.Provider].ClientID}).Verify(ctx, raw)
	if err != nil || idToken.Nonce != flow.Nonce {
		fail(http.StatusForbidden, "login-failed", "The login provider's identity token is invalid.", err)
		return
	}
	var claims struct {
		Email    string `json:"email"`
		Verified *bool  `json:"email_verified"`
	}
	if err := idToken.Claims(&claims); err != nil || claims.Email == "" || (claims.Verified != nil && !*claims.Verified) {
		fail(http.StatusForbidden, "login-failed", "The login provider didn't return a verified email address.", err)
		return
	}
	if s.ruleFor(flow.Login.Host) == nil {
		fail(http.StatusBadGateway, "agent-offline", "The tunnel went offline during the login.", nil)
		return
	}
	code, err := s.signer.sign(purposeCode, loginCode{Email: strings.ToLower(claims.Email), Host: flow.Login.Host,
		Path: flow.Login.Path, ID: randomString(12), Exp: time.Now().Add(codeTTL).Unix()})
	if err != nil {
		fail(http.StatusInternalServerError, "login-error", "Could not finish the login.", err)
		return
	}
	http.Redirect(w, r, "https://"+flow.Login.Host+AuthPath+"?code="+url.QueryEscape(code), http.StatusFound)
}

func (s *Service) ruleFor(host string) *auth.OIDCRule {
	b := s.binding()
	if b.RuleFor == nil {
		return nil
	}
	return b.RuleFor(normalizeHost(host))
}

// authURL is an absolute URL on the auth host.
func (s *Service) authURL(path string) string {
	host := s.cfg.AuthHost
	if b := s.binding(); b.HTTPSPort != nil && b.HTTPSPort() != 443 {
		host = net.JoinHostPort(host, strconv.Itoa(b.HTTPSPort()))
	}
	return "https://" + host + path
}

// provider discovers (once) and returns a provider.
func (s *Service) provider(ctx context.Context, name string) (*gooidc.Provider, error) {
	s.mu.Lock()
	p := s.providers[name]
	s.mu.Unlock()
	if p != nil {
		return p, nil
	}
	pc, ok := s.cfg.Providers[name]
	if !ok {
		return nil, fmt.Errorf("provider %q is not configured", name)
	}
	p, err := gooidc.NewProvider(gooidc.ClientContext(ctx, s.cfg.HTTPClient), pc.Issuer)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	s.providers[name] = p
	s.mu.Unlock()
	return p, nil
}

func (s *Service) oauthConfig(ctx context.Context, name string) (*oauth2.Config, error) {
	p, err := s.provider(ctx, name)
	if err != nil {
		return nil, err
	}
	pc := s.cfg.Providers[name]
	scopes := pc.Scopes
	if len(scopes) == 0 {
		scopes = []string{gooidc.ScopeOpenID, "email", "profile"}
	}
	return &oauth2.Config{ClientID: pc.ClientID, ClientSecret: pc.ClientSecret, Endpoint: p.Endpoint(),
		RedirectURL: s.authURL("/callback"), Scopes: scopes}, nil
}

// normalizeHost lowercases a host and drops its port and trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

// safePath keeps redirects on the same host.
func safePath(p string) string {
	if !strings.HasPrefix(p, "/") || strings.HasPrefix(p, "//") || strings.HasPrefix(p, "/\\") {
		return "/"
	}
	return p
}

// stripCookie removes one cookie from a request before it's proxied.
func stripCookie(r *http.Request, name string) {
	cookies := r.Cookies()
	r.Header.Del("Cookie")
	for _, c := range cookies {
		if c.Name != name {
			r.AddCookie(c)
		}
	}
}
