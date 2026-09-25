package tests

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8types/go/types/l8api"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// KindURLEnv points the Layer 8 tests at a deployed l8tunnel, for example
// https://localhost:5443 after k8s/kind-start.sh. Without it they skip:
// the management plane is tested inside KIND only.
const KindURLEnv = "L8TUNNEL_KIND_URL"

// kindClient calls the management REST API as one user.
type kindClient struct {
	t     *testing.T
	base  string
	token string
	http  *http.Client
}

// newKindClient logs in, or skips the test when no deployment is set.
func newKindClient(t *testing.T, user, password string) *kindClient {
	t.Helper()
	base := os.Getenv(KindURLEnv)
	if base == "" {
		t.Skipf("set %s to run the management-plane tests against KIND", KindURLEnv)
	}
	c := &kindClient{t: t, base: strings.TrimSuffix(base, "/"), http: &http.Client{
		Timeout: 60 * time.Second,
		// The web server's certificate is self-signed in KIND.
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
	}}
	body, _ := json.Marshal(map[string]string{"user": user, "pass": password})
	resp, err := c.http.Post(c.base+"/auth", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("login as %s: %v", user, err)
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	var out map[string]interface{}
	if resp.StatusCode != http.StatusOK || json.Unmarshal(data, &out) != nil || out["token"] == nil {
		t.Fatalf("login as %s: status %d: %s", user, resp.StatusCode, data)
	}
	c.token = out["token"].(string)
	return c
}

func (c *kindClient) url(area byte, service string) string {
	return fmt.Sprintf("%s/%s/%d/%s", c.base, strings.Trim(common.PREFIX, "/"), area, service)
}

// do sends msg (protojson) and decodes the reply into out (nil: ignore).
// A non-2xx status, or a reply carrying an error, is returned as an error.
func (c *kindClient) do(method string, area byte, service string, msg proto.Message, out proto.Message) error {
	var body io.Reader
	target := c.url(area, service)
	if msg != nil {
		data, err := protojson.Marshal(msg)
		if err != nil {
			return err
		}
		if method == http.MethodGet {
			target += "?body=" + url.QueryEscape(string(data))
		} else {
			body = bytes.NewReader(data)
		}
	}
	req, err := http.NewRequest(method, target, body)
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.token)
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return fmt.Errorf("%s %s: status %d: %s", method, service, resp.StatusCode, strings.TrimSpace(string(data)))
	}
	if msg := replyError(data); msg != "" {
		return fmt.Errorf("%s %s: %s", method, service, msg)
	}
	if out != nil && len(bytes.TrimSpace(data)) > 0 {
		if err := (protojson.UnmarshalOptions{DiscardUnknown: true}).Unmarshal(data, out); err != nil {
			return fmt.Errorf("%s %s: decode %s: %w", method, service, data, err)
		}
	}
	return nil
}

// replyError extracts an error message from a JSON reply, if it has one.
func replyError(data []byte) string {
	var m map[string]interface{}
	if json.Unmarshal(data, &m) != nil {
		return ""
	}
	for _, k := range []string{"error", "Error", "errorMessage"} {
		if s, ok := m[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// query GETs with an L8Query text.
func (c *kindClient) query(area byte, service, text string, out proto.Message) error {
	return c.do(http.MethodGet, area, service, &l8api.L8Query{Text: text}, out)
}

// mustDo fails the test on an error.
func (c *kindClient) mustDo(method string, area byte, service string, msg, out proto.Message) {
	c.t.Helper()
	if err := c.do(method, area, service, msg, out); err != nil {
		c.t.Fatal(err)
	}
}

// expectRefused fails unless the request is refused with an error that
// mentions want.
func (c *kindClient) expectRefused(what, want, method string, area byte, service string, msg proto.Message) {
	c.t.Helper()
	err := c.do(method, area, service, msg, nil)
	if err == nil {
		c.t.Errorf("%s: accepted", what)
		return
	}
	if want != "" && !strings.Contains(err.Error(), want) {
		c.t.Errorf("%s: refused with %q, want a message about %q", what, err, want)
	}
}

// uniqueName is a name no earlier test run left behind.
func uniqueName(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, time.Now().UnixNano()%1_000_000_000)
}

// remove deletes the objects an L8Query where-clause selects (REST
// deletes take a query, not an object).
func (c *kindClient) remove(area byte, service, typeName, where string) error {
	return c.do(http.MethodDelete, area, service, &l8api.L8Query{Text: "select * from " + typeName + " where " + where}, nil)
}
