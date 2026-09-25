package oidc

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"time"
)

// Payloads carried in URLs and cookies are JSON, base64url-encoded and
// HMAC-SHA256 signed. The purpose is part of the signed data, so a value
// minted for one use (say a login code) can't be replayed as another
// (say a session cookie).

var errBadSignature = errors.New("invalid or expired signature")

type signer struct {
	key []byte
}

func (s signer) sign(purpose string, v interface{}) (string, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	body := base64.RawURLEncoding.EncodeToString(data)
	return body + "." + base64.RawURLEncoding.EncodeToString(s.mac(purpose, body)), nil
}

// verify checks the signature and decodes into v. The payload's own Exp
// field is checked by the caller (see expired).
func (s signer) verify(purpose, token string, v interface{}) error {
	body, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errBadSignature
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(purpose, body)) {
		return errBadSignature
	}
	data, err := base64.RawURLEncoding.DecodeString(body)
	if err != nil {
		return errBadSignature
	}
	return json.Unmarshal(data, v)
}

func (s signer) mac(purpose, body string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(purpose + "\x00" + body))
	return m.Sum(nil)
}

func expired(exp int64) bool {
	return time.Now().Unix() > exp
}

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

// Purposes.
const (
	purposeLogin   = "login-state"    // tunnel host -> auth host
	purposeFlow    = "flow-cookie"    // auth host cookie during the IdP round trip
	purposeCode    = "login-code"     // auth host -> tunnel host, single use
	purposeSession = "session-cookie" // tunnel host cookie
)

// loginState is where a login started.
type loginState struct {
	Host string `json:"h"` // tunnel host as the browser sent it (may include :port)
	Path string `json:"p"` // request URI to return to
	Exp  int64  `json:"e"`
}

// flowCookie binds the IdP callback to the browser that started the login.
type flowCookie struct {
	Nonce    string     `json:"n"`
	Verifier string     `json:"v"` // PKCE
	Provider string     `json:"pr"`
	Login    loginState `json:"l"`
	Exp      int64      `json:"e"`
}

// loginCode hands a verified identity to the tunnel host.
type loginCode struct {
	Email string `json:"m"`
	Host  string `json:"h"`
	Path  string `json:"p"`
	ID    string `json:"i"` // single-use nonce
	Exp   int64  `json:"e"`
}

// session is the tunnel host's cookie.
type session struct {
	Email string `json:"m"`
	Host  string `json:"h"` // normalized host name
	Exp   int64  `json:"e"`
}
