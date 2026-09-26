package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"github.com/saichler/l8tunnel/go/types/tun"
	"golang.org/x/crypto/bcrypt"
	"golang.org/x/crypto/ssh"
)

const (
	post  = http.MethodPost
	put   = http.MethodPut
	patch = http.MethodPatch
)

// issueToken creates a token through TunIssue and returns the reply.
func issueToken(t *testing.T, c *kindClient, name string, policy *tun.TunTokenPolicy) *tun.TunIssueResponse {
	t.Helper()
	resp := &tun.TunIssueResponse{}
	c.mustDo(post, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{
		Kind: tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN, TokenName: name, Policy: policy}, resp)
	return resp
}

// revokeToken revokes through TunIssue (cleanup and the revoke test).
func revokeToken(c *kindClient, tokenID string) (*tun.TunIssueResponse, error) {
	resp := &tun.TunIssueResponse{}
	err := c.do(post, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{
		Kind: tun.TunIssueKind_TUN_ISSUE_KIND_REVOKE, TokenId: tokenID}, resp)
	return resp, err
}

func getToken(t *testing.T, c *kindClient, id string) *tun.TunToken {
	t.Helper()
	list := &tun.TunTokenList{}
	if err := c.query(common.AreaAccess, common.TokenService, "select * from TunToken where tokenId="+id, list); err != nil {
		t.Fatal(err)
	}
	for _, tok := range list.List {
		if tok.TokenId == id {
			return tok
		}
	}
	return nil
}

func TestKindTokens(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	name := uniqueName("kt")
	resp := issueToken(t, c, name, &tun.TunTokenPolicy{Types: []tun.TunTunnelType{tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH}, MaxTunnels: 2})
	t.Cleanup(func() { revokeToken(c, resp.TokenId) })
	id, secret, err := auth.ParseToken(resp.Token)
	if err != nil || id != resp.TokenId || secret == "" {
		t.Fatalf("issued token %q (id %s): %v", resp.Token, resp.TokenId, err)
	}

	tok := getToken(t, c, id)
	if tok == nil || tok.Name != name || tok.Policy.GetMaxTunnels() != 2 {
		t.Fatalf("stored token %+v", tok)
	}
	// Even an admin never sees the hash (field-level deny rule).
	if tok.SecretHash != "" {
		t.Fatalf("the secret hash reached the UI: %q", tok.SecretHash)
	}

	c.expectRefused("duplicate name", "already exists", post, common.AreaAccess, common.IssueService,
		&tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN, TokenName: name})
	c.expectRefused("bad name", "token name", post, common.AreaAccess, common.IssueService,
		&tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN, TokenName: "no spaces"})
	c.expectRefused("bad policy", "port range", post, common.AreaAccess, common.IssueService,
		&tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN, TokenName: uniqueName("kt"),
			Policy: &tun.TunTokenPolicy{Ports: "9-1"}})
	c.expectRefused("POST without TunIssue", "TunIssue", post, common.AreaAccess, common.TokenService,
		&tun.TunToken{Name: uniqueName("kt")})

	// A PUT from the UI (hash blanked) keeps the stored secret; a new hash
	// is refused.
	tok.Description = "edited"
	c.mustDo(put, common.AreaAccess, common.TokenService, tok, nil)
	if got := getToken(t, c, id); got.Description != "edited" {
		t.Fatalf("PUT not applied: %+v", got)
	}
	hash, _ := bcrypt.GenerateFromPassword([]byte("other"), bcrypt.MinCost)
	tok.SecretHash = string(hash)
	c.expectRefused("changing the secret", "can't be changed", put, common.AreaAccess, common.TokenService, tok)
}

func TestKindReservationsAndGatewayKeys(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	resp := issueToken(t, c, uniqueName("kr"), nil)
	t.Cleanup(func() { revokeToken(c, resp.TokenId) })

	name := uniqueName("box")
	c.mustDo(post, common.AreaAccess, common.ReservationService, &tun.TunReservation{Name: name, TokenId: resp.TokenId, PublicPort: 22123}, nil)
	for what, r := range map[string]*tun.TunReservation{
		"duplicate name":     {Name: name, TokenId: resp.TokenId},
		"duplicate port":     {Name: uniqueName("box"), TokenId: resp.TokenId, PublicPort: 22123},
		"reserved name":      {Name: "www", TokenId: resp.TokenId},
		"control host":       {Name: "connect", TokenId: resp.TokenId},
		"port outside range": {Name: uniqueName("box"), TokenId: resp.TokenId, PublicPort: 80},
		"unknown token":      {Name: uniqueName("box"), TokenId: "nosuch"},
		"invalid name":       {Name: "Box_1", TokenId: resp.TokenId},
	} {
		c.expectRefused(what, "", post, common.AreaAccess, common.ReservationService, r)
	}

	// A claim right after the reservation gets its port, and another token
	// can't take the name.
	ca := installTunnelCert(t, c)
	a := waitReady(t, kindAgent(t, ca, kindRelay0TLS, resp.Token, uniqueName("ragent"),
		agent.TunnelConfig{Name: name, Type: tcpType, Target: startEchoServer(t)}))
	if port := a.agent.Endpoints()[0].GetPublicPort(); port != 22123 {
		t.Fatalf("reserved port: got %d, want 22123", port)
	}
	stopAgent(t, a)
	other := issueToken(t, c, uniqueName("kro"), nil)
	t.Cleanup(func() { revokeToken(c, other.TokenId) })
	if err := runAgentKindExpectError(t, ca, kindRelay1TLS, other.Token,
		agent.TunnelConfig{Name: name, Type: tcpType, Target: startEchoServer(t)}); err == nil {
		t.Fatal("another token claimed a reserved name")
	}

	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sshPub, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))) + " alice@laptop"
	keyName := uniqueName("alice")
	c.mustDo(post, common.AreaAccess, common.GatewayKeyService, &tun.TunGatewayKey{Name: keyName, PublicKey: line, Tunnels: []string{"home*"}}, nil)
	keys := &tun.TunGatewayKeyList{}
	if err := c.query(common.AreaAccess, common.GatewayKeyService, "select * from TunGatewayKey where name="+keyName, keys); err != nil {
		t.Fatal(err)
	}
	if len(keys.List) != 1 || keys.List[0].Fingerprint != ssh.FingerprintSHA256(sshPub) {
		t.Fatalf("stored gateway keys %+v", keys.List)
	}
	c.expectRefused("same key twice", "already registered", post, common.AreaAccess, common.GatewayKeyService,
		&tun.TunGatewayKey{Name: uniqueName("bob"), PublicKey: line, Tunnels: []string{"x"}})
	c.expectRefused("no grants", "grant", post, common.AreaAccess, common.GatewayKeyService,
		&tun.TunGatewayKey{Name: uniqueName("bob"), PublicKey: line})
	c.expectRefused("not a key", "public key", post, common.AreaAccess, common.GatewayKeyService,
		&tun.TunGatewayKey{Name: uniqueName("bob"), PublicKey: "ssh-ed25519 garbage", Tunnels: []string{"x"}})
	if err := c.remove(common.AreaAccess, common.GatewayKeyService, "TunGatewayKey", "keyId="+keys.List[0].KeyId); err != nil {
		t.Fatal(err)
	}
}

func TestKindAgentCertsAndRevoke(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	resp := issueToken(t, c, uniqueName("kc"), nil)
	c.mustDo(post, common.AreaAccess, common.ReservationService, &tun.TunReservation{Name: uniqueName("cbox"), TokenId: resp.TokenId}, nil)

	cert := &tun.TunIssueResponse{}
	c.mustDo(post, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{
		Kind: tun.TunIssueKind_TUN_ISSUE_KIND_AGENT_CERT, TokenId: resp.TokenId, CertDays: 30}, cert)
	if !strings.Contains(cert.CertPem, "BEGIN CERTIFICATE") || !strings.Contains(cert.KeyPem, "PRIVATE KEY") || cert.CertId == "" {
		t.Fatalf("issued certificate %+v", cert)
	}
	certs := &tun.TunAgentCertList{}
	if err := c.query(common.AreaAccess, common.AgentCertService, "select * from TunAgentCert where certId="+cert.CertId, certs); err != nil {
		t.Fatal(err)
	}
	if len(certs.List) != 1 || certs.List[0].TokenId != resp.TokenId || certs.List[0].Fingerprint == "" {
		t.Fatalf("certificate record %+v", certs.List)
	}
	rec := certs.List[0]
	rec.TokenId = "other"
	c.expectRefused("moving a certificate to another token", "revoked", put, common.AreaAccess, common.AgentCertService, rec)
	c.mustDo(patch, common.AreaAccess, common.AgentCertService, &tun.TunAgentCert{CertId: cert.CertId, Revoked: true}, nil)

	out, err := revokeToken(c, resp.TokenId)
	if err != nil || out.RevokedCerts != 1 || out.RemovedReservations != 1 {
		t.Fatalf("revoke: %+v %v", out, err)
	}
	if getToken(t, c, resp.TokenId) != nil {
		t.Fatal("the token still exists after revoke")
	}
	if _, err := revokeToken(c, resp.TokenId); err == nil {
		t.Fatal("revoking a missing token succeeded")
	}
}

func TestKindImportStandaloneExport(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	// A standalone relay's database with one token (cert serial and
	// reservation included), exported as l8tunnel-server export would.
	st, err := store.Open(filepath.Join(t.TempDir(), "l8tunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	plaintext, rec, err := auth.NewToken(uniqueName("imp"), auth.Policy{Types: []string{"ssh"}})
	if err != nil {
		t.Fatal(err)
	}
	rec.CertSerials = []string{"feed" + rec.ID}
	if err := st.AddToken(rec); err != nil {
		t.Fatal(err)
	}
	boxName := uniqueName("impbox")
	if err := st.PutReservation(&store.Reservation{Name: boxName, TokenID: rec.ID, Port: 22321}); err != nil {
		t.Fatal(err)
	}
	exp, err := st.Export()
	if err != nil {
		t.Fatal(err)
	}
	data := mustJSON(t, exp)
	out := &tun.TunIssueResponse{}
	c.mustDo(post, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_IMPORT, ImportJson: data}, out)
	t.Cleanup(func() { revokeToken(c, rec.ID) })
	if out.ImportedTokens != 1 || out.ImportedReservations != 1 {
		t.Fatalf("import result %+v", out)
	}
	// The same token ID, so the agent's existing token string keeps working.
	if tok := getToken(t, c, rec.ID); tok == nil || tok.Name != rec.Name {
		t.Fatalf("imported token %+v (plaintext %s)", tok, plaintext)
	}
	// An agent connects with the token it already had and gets its
	// reserved port.
	ca := installTunnelCert(t, c)
	a := waitReady(t, kindAgent(t, ca, kindRelay0TLS, plaintext, uniqueName("impagent"),
		agent.TunnelConfig{Name: boxName, Type: sshType, Target: startEchoServer(t)}))
	if port := a.agent.Endpoints()[0].GetPublicPort(); port != 22321 {
		t.Fatalf("imported reservation: port %d, want 22321", port)
	}
	stopAgent(t, a)
	// Re-running the import adds nothing.
	again := &tun.TunIssueResponse{}
	c.mustDo(post, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_IMPORT, ImportJson: data}, again)
	if again.ImportedTokens != 0 || again.ImportedReservations != 0 {
		t.Fatalf("second import %+v", again)
	}
}
