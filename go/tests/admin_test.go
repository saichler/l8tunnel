package tests

import (
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/store"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
	"golang.org/x/crypto/bcrypt"
)

// startAdmin serves the relay's admin API on a socket in a temp dir.
func startAdmin(t *testing.T, env *relayEnv) string {
	t.Helper()
	socket := filepath.Join(t.TempDir(), "admin.sock")
	ln, err := admin.ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	go admin.Serve(t.Context(), ln, admin.RelayHandler(env.srv, env.store, testLogger()), testLogger())
	return socket
}

func adminCmd(t *testing.T, socket string, args ...string) (string, error) {
	t.Helper()
	var out bytes.Buffer
	err := admin.RunServerCommand(socket, args, &out, io.Discard)
	return out.String(), err
}

func mustAdmin(t *testing.T, socket string, args ...string) string {
	t.Helper()
	out, err := adminCmd(t, socket, args...)
	if err != nil {
		t.Fatalf("%v: %v", args, err)
	}
	return out
}

var printedToken = regexp.MustCompile(`(?m)^\s+(l8t_\S+)$`)

func TestAdminCLIManagesTokensAndReservations(t *testing.T) {
	env := startRelay(t, 2)
	socket := startAdmin(t, env)

	out := mustAdmin(t, socket, "token", "create", "--name", "ci", "--types", "tcp,http", "--max-tunnels", "3")
	m := printedToken.FindStringSubmatch(out)
	if m == nil {
		t.Fatalf("no token in output:\n%s", out)
	}
	ciToken := m[1]
	if _, err := adminCmd(t, socket, "token", "create", "--name", "ci"); err == nil {
		t.Fatal("a second token named ci was created")
	}

	ra := waitReady(t, runAgent(t, newAgent(t, env, ciToken, agent.TunnelConfig{Name: "ci-box", Type: tcpType, Target: startEchoServer(t)})))

	if out := mustAdmin(t, socket, "token", "list"); !strings.Contains(out, "ci") || !strings.Contains(out, "types=tcp,http max-tunnels=3") ||
		strings.Contains(out, ciToken) {
		t.Fatalf("token list:\n%s", out)
	}
	if out := mustAdmin(t, socket, "status"); !strings.Contains(out, "ci-box") || !strings.Contains(out, "AGENTS (1)") {
		t.Fatalf("status:\n%s", out)
	}

	mustAdmin(t, socket, "reservation", "add", "--name", "ci-box", "--token", "ci")
	if _, err := adminCmd(t, socket, "reservation", "add", "--name", "ci-box", "--token", "test"); err == nil ||
		!strings.Contains(err.Error(), "another token") {
		t.Fatalf("conflicting reservation: %v", err)
	}
	if out := mustAdmin(t, socket, "reservation", "list"); !strings.Contains(out, "ci-box") {
		t.Fatalf("reservation list:\n%s", out)
	}

	if out := mustAdmin(t, socket, "token", "revoke", "ci"); !strings.Contains(out, "disconnected 1") {
		t.Fatalf("revoke: %s", out)
	}
	select {
	case err := <-ra.done:
		ra.done <- err
		expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	case <-time.After(5 * time.Second):
		t.Fatal("agent still running after its token was revoked")
	}
	if out := mustAdmin(t, socket, "reservation", "list"); strings.Contains(out, "ci-box") {
		t.Fatalf("the revoked token's reservation survived:\n%s", out)
	}

	for _, bad := range [][]string{{"token", "revoke", "nobody"}, {"reservation", "remove", "nothing"}, {"frobnicate"}, {}} {
		if _, err := adminCmd(t, socket, bad...); err == nil {
			t.Errorf("%v succeeded", bad)
		}
	}
}

func TestRelayStatusCountsConnectionsAndBytes(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "count", Type: tcpType, Target: startEchoServer(t)})
	payload := bytes.Repeat([]byte("x"), 1000)
	if _, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), payload); err != nil {
		t.Fatal(err)
	}
	waitUntil(t, 5*time.Second, "counters to settle", func() bool {
		st := env.srv.Status()
		if len(st.Sessions) != 1 || len(st.Sessions[0].Tunnels) != 1 {
			return false
		}
		tun := st.Sessions[0].Tunnels[0]
		return tun.TotalConns == 1 && tun.ActiveConns == 0 && tun.BytesIn == 1000 && tun.BytesOut == 1000
	})
	s := env.srv.Status().Sessions[0]
	if s.Token != "test" || s.Version != "test" || s.AgentID == "" {
		t.Fatalf("session status %+v", s)
	}
}

func TestAgentStatusSocket(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "stat", Type: tcpType, Target: startEchoServer(t)})
	socket := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := admin.ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	go admin.Serve(t.Context(), ln, admin.AgentHandler(ra.agent), testLogger())

	if _, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), []byte("hello")); err != nil {
		t.Fatal(err)
	}
	var st agent.Status
	waitUntil(t, 5*time.Second, "agent counters", func() bool {
		var out bytes.Buffer
		if err := admin.RunAgentStatus(socket, true, &out); err != nil {
			return false
		}
		st = agent.Status{}
		return json.Unmarshal(out.Bytes(), &st) == nil && len(st.Tunnels) == 1 && st.Tunnels[0].BytesIn == 5
	})
	if !st.Connected || st.Tunnels[0].Name != "stat" || st.Tunnels[0].TotalConns != 1 || st.Tunnels[0].PublicAddress == "" {
		t.Fatalf("agent status %+v", st)
	}
	var table bytes.Buffer
	if err := admin.RunAgentStatus(socket, false, &table); err != nil || !strings.Contains(table.String(), "connected for") {
		t.Fatalf("status table %q, %v", table.String(), err)
	}
}

func TestAdminSocketSafety(t *testing.T) {
	dir := t.TempDir()
	socket := filepath.Join(dir, "a.sock")
	ln, err := admin.ListenUnix(socket)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(socket)
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode %v, %v; want 0600", fi.Mode().Perm(), err)
	}
	if _, err := admin.ListenUnix(socket); err == nil || !strings.Contains(err.Error(), "in use") {
		t.Fatalf("second listener on a live socket: %v", err)
	}
	ln.Close()
	// Go removes the socket file on Close; recreate a stale one.
	os.WriteFile(filepath.Join(dir, "plain"), []byte("x"), 0o600)
	if _, err := admin.ListenUnix(filepath.Join(dir, "plain")); err == nil {
		t.Fatal("ListenUnix replaced a regular file")
	}
	long := "/tmp/" + strings.Repeat("x", 120) + ".sock"
	if _, err := admin.ListenUnix(long); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("over-long socket path: %v", err)
	}
	if _, err := admin.NewClient(long).Tokens(); err == nil || !strings.Contains(err.Error(), "at most") {
		t.Fatalf("client with an over-long socket path: %v", err)
	}
	if _, err := admin.NewClient(filepath.Join(dir, "missing.sock")).Tokens(); err == nil ||
		!strings.Contains(err.Error(), "is the process running") {
		t.Fatalf("client on a missing socket: %v", err)
	}
}

func TestStorePersistsAndLocks(t *testing.T) {
	path := filepath.Join(t.TempDir(), "db", "l8tunnel.db")
	st, err := store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	rec, err := auth.NewTokenRecord("laptop", testToken, auth.Policy{Types: []string{"ssh"}}, bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddToken(rec); err != nil {
		t.Fatal(err)
	}
	dup, _ := auth.NewTokenRecord("laptop", otherToken, auth.Policy{}, bcrypt.MinCost)
	if err := st.AddToken(dup); err == nil {
		t.Fatal("duplicate token name accepted")
	}
	if err := st.PutReservation(storeReservation("home", rec.ID, 22001)); err != nil {
		t.Fatal(err)
	}
	if err := st.PutReservation(storeReservation("x", "00000000", 0)); err == nil {
		t.Fatal("reservation for an unknown token accepted")
	}

	start := time.Now()
	if _, err := store.Open(path); err == nil || !strings.Contains(err.Error(), "locked") {
		t.Fatalf("second open: %v, want a lock error", err)
	}
	if time.Since(start) > 3*time.Second {
		t.Fatal("second open waited too long for the lock")
	}
	st.Close()

	st, err = store.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	got, err := st.TokenByID(rec.ID)
	if err != nil || got == nil || got.Name != "laptop" || got.Policy.Types[0] != "ssh" {
		t.Fatalf("token after reopen: %+v, %v", got, err)
	}
	_, secret, _ := auth.ParseToken(testToken)
	if !got.Verify(secret) || got.Verify("wrong") {
		t.Fatal("stored hash doesn't verify the secret")
	}
	if err := st.DeleteToken(rec.ID); err != nil {
		t.Fatal(err)
	}
	if list, _ := st.Reservations(); len(list) != 0 {
		t.Fatalf("reservations survived their token: %+v", list)
	}
}

func TestAdminExportForKubernetes(t *testing.T) {
	env := startRelay(t, 2)
	socket := startAdmin(t, env)
	mustAdmin(t, socket, "reservation", "add", "--name", "kept", "--token", "test", "--port", strconv.Itoa(env.portMin))
	dir := filepath.Join(t.TempDir(), "export")
	out := mustAdmin(t, socket, "export", "--out", dir)
	if !strings.Contains(out, "exported 2 tokens, 1 reservations") {
		t.Fatalf("export output: %s", out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "export.json"))
	if err != nil {
		t.Fatal(err)
	}
	exp, err := store.ParseExport(data)
	if err != nil || len(exp.Tokens) != 2 || exp.Reservations[0].Name != "kept" || len(exp.Tokens[0].Hash) == 0 {
		t.Fatalf("export %+v %v", exp, err)
	}
	for _, f := range []string{"export.json", "ca.crt", "ca.key"} {
		info, err := os.Stat(filepath.Join(dir, f))
		if err != nil || info.Mode().Perm() != 0o600 {
			t.Fatalf("%s: %v %v", f, info, err)
		}
	}
	certPEM, _ := os.ReadFile(filepath.Join(dir, "ca.crt"))
	keyPEM, _ := os.ReadFile(filepath.Join(dir, "ca.key"))
	if _, err := auth.LoadAgentCA(certPEM, keyPEM); err != nil {
		t.Fatalf("exported agent CA: %v", err)
	}
	if _, err := adminCmd(t, socket, "export", "--out", dir); err == nil {
		t.Fatal("a second export overwrote the files")
	}
}
