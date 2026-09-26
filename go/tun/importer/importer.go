// Package importer loads a standalone relay's export (the export.json that
// "l8tunnel-server export" writes) into the cluster through TunIssue
// IMPORT: its tokens, reservations and gateway keys, keeping their IDs, so
// the agents reconnect unchanged (plan §7.5). The agent CA from the same
// export goes in with k8s/secrets.sh.
package importer

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"google.golang.org/protobuf/encoding/protojson"
)

// Import posts the export file to the l8tunnel web server at address as
// user and returns what was imported.
func Import(address, user, password, exportFile string, insecure bool) (*tun.TunIssueResponse, error) {
	data, err := os.ReadFile(exportFile)
	if err != nil {
		return nil, err
	}
	client := &http.Client{Timeout: 60 * time.Second}
	if insecure {
		client.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	token, err := login(client, address, user, password)
	if err != nil {
		return nil, err
	}
	body, err := protojson.Marshal(&tun.TunIssueRequest{Kind: tun.TunIssueKind_TUN_ISSUE_KIND_IMPORT, ImportJson: string(data)})
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequest(http.MethodPost, fmt.Sprintf("%s/tun/%d/%s", address, common.AreaAccess, common.IssueService), bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("import refused (HTTP %d): %s", resp.StatusCode, respBody)
	}
	out := &tun.TunIssueResponse{}
	if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(respBody, out); err != nil {
		return nil, fmt.Errorf("import reply: %w", err)
	}
	return out, nil
}

func login(client *http.Client, address, user, password string) (string, error) {
	body, _ := json.Marshal(map[string]string{"user": user, "pass": password})
	resp, err := client.Post(address+"/auth", "application/json", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var out map[string]interface{}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out["token"] == nil {
		return "", fmt.Errorf("login as %s failed (HTTP %d)", user, resp.StatusCode)
	}
	return out["token"].(string), nil
}
