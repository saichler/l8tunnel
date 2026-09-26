package mocks

import (
	"encoding/json"
	"fmt"
	"net/http"

	l8m "github.com/saichler/l8common/go/mocks"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// Client is the shared Layer 8 mock client (authenticated POSTs).
type Client = l8m.MockClient

func NewClient(baseURL string, httpClient *http.Client) *Client {
	return l8m.NewMockClient(baseURL, httpClient)
}

// endpoint is /tun/<area>/<ServiceName>.
func endpoint(area byte, service string) string {
	return fmt.Sprintf("/tun/%d/%s", area, service)
}

// post sends a protobuf message as protojson and decodes the reply into out
// (when out isn't nil).
func post(c *Client, area byte, service string, msg, out proto.Message) error {
	body, err := protojson.Marshal(msg)
	if err != nil {
		return err
	}
	resp, err := c.Post(endpoint(area, service), json.RawMessage(body))
	if err != nil {
		return fmt.Errorf("%s: %w", service, err)
	}
	if out == nil {
		return nil
	}
	return protojson.UnmarshalOptions{DiscardUnknown: true}.Unmarshal([]byte(resp), out)
}

// postMap sends a plain JSON object (the Security API takes maps; a
// project never imports l8secure).
func postMap(c *Client, area byte, service string, obj map[string]interface{}) error {
	if _, err := c.Post(endpoint(area, service), obj); err != nil {
		return fmt.Errorf("%s: %w", service, err)
	}
	return nil
}
