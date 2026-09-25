package admin

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"

	"github.com/saichler/l8tunnel/go/tunnel/store"
)

// ExportResponse is the body of GET /export: the relay's tokens,
// reservations and gateway keys, and its agent CA.
type ExportResponse struct {
	Export *store.Export `json:"export"`
	CACert string        `json:"ca_cert"`
	CAKey  string        `json:"ca_key"`
}

func (a *relayAPI) export(w http.ResponseWriter, _ *http.Request) {
	exp, err := a.st.Export()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	ca, err := a.st.AgentCA()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	certPEM, keyPEM, err := ca.PEM()
	if err != nil {
		writeErr(w, http.StatusInternalServerError, err)
		return
	}
	a.log.Info("state exported", "tokens", len(exp.Tokens), "reservations", len(exp.Reservations), "gateway_keys", len(exp.GatewayKeys))
	writeJSON(w, http.StatusOK, ExportResponse{Export: exp, CACert: string(certPEM), CAKey: string(keyPEM)})
}

// Export fetches the relay's state for moving it to Kubernetes.
func (c *Client) Export() (*ExportResponse, error) {
	out := &ExportResponse{}
	return out, c.do(http.MethodGet, "/export", nil, out)
}

// exportCommand writes DIR/export.json (for TunIssue IMPORT) and the agent
// CA as DIR/ca.crt and DIR/ca.key (for k8s/secrets.sh). The files contain
// token hashes and the CA key: they are written 0600 and never overwritten.
func exportCommand(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	out := fs.String("out", "", "directory for export.json, ca.crt and ca.key")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *out == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: export --out DIR")
	}
	resp, err := c.Export()
	if err != nil {
		return err
	}
	data, err := json.MarshalIndent(resp.Export, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(*out, 0o700); err != nil {
		return err
	}
	for name, content := range map[string][]byte{"export.json": data, "ca.crt": []byte(resp.CACert), "ca.key": []byte(resp.CAKey)} {
		if err := writeNewFile(filepath.Join(*out, name), content, 0o600); err != nil {
			return err
		}
	}
	fmt.Fprintf(stdout, "exported %d tokens, %d reservations, %d gateway keys and the agent CA to %s\n",
		len(resp.Export.Tokens), len(resp.Export.Reservations), len(resp.Export.GatewayKeys), *out)
	return nil
}
