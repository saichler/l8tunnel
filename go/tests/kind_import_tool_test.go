package tests

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/saichler/l8tunnel/go/tun/importer"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/store"
)

// TestKindImportTool: the import command loads a standalone relay's
// export.json, as "l8tunnel-server export" writes it, into the cluster.
func TestKindImportTool(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	st, err := store.Open(filepath.Join(t.TempDir(), "l8tunnel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	_, rec, err := auth.NewToken(uniqueName("tool"), auth.Policy{Types: []string{"http"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := st.AddToken(rec); err != nil {
		t.Fatal(err)
	}
	if err := st.PutReservation(&store.Reservation{Name: uniqueName("toolbox"), TokenID: rec.ID}); err != nil {
		t.Fatal(err)
	}
	exp, err := st.Export()
	if err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "export.json")
	if err := os.WriteFile(file, []byte(mustJSON(t, exp)), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := importer.Import(os.Getenv(KindURLEnv), "admin", "admin", file, true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { revokeToken(c, rec.ID) })
	if out.ImportedTokens != 1 || out.ImportedReservations != 1 {
		t.Fatalf("import result %+v", out)
	}
	if tok := getToken(t, c, rec.ID); tok == nil || tok.Name != rec.Name {
		t.Fatalf("imported token %+v", tok)
	}
	if _, err := importer.Import(os.Getenv(KindURLEnv), "admin", "wrong", file, true); err == nil {
		t.Fatal("a wrong password was accepted")
	}
}
