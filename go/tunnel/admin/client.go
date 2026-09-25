package admin

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
)

// Client calls an admin socket.
type Client struct {
	socket string
	http   *http.Client
}

// NewClient returns a client for the socket at path.
func NewClient(path string) *Client {
	return &Client{
		socket: path,
		http: &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", path)
				},
			},
		},
	}
}

// do sends a request and decodes a JSON response into out (if not nil).
func (c *Client) do(method, path string, body, out interface{}) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	if err := checkSocketPath(c.socket); err != nil {
		return err
	}
	req, err := http.NewRequest(method, "http://admin"+path, reader)
	if err != nil {
		return err
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin socket %s: %w (is the process running, and can this user open the socket?)", c.socket, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		var e apiError
		if json.NewDecoder(resp.Body).Decode(&e) == nil && e.Error != "" {
			return fmt.Errorf("%s", e.Error)
		}
		return fmt.Errorf("admin socket: %s", resp.Status)
	}
	if out == nil {
		return nil
	}
	return json.NewDecoder(resp.Body).Decode(out)
}

// RelayStatus returns the relay's status.
func (c *Client) RelayStatus() (relay.Status, error) {
	var st relay.Status
	err := c.do("GET", "/status", nil, &st)
	return st, err
}

// CreateToken creates a token; the response carries its only copy.
func (c *Client) CreateToken(req CreateTokenRequest) (CreateTokenResponse, error) {
	var resp CreateTokenResponse
	err := c.do("POST", "/tokens", req, &resp)
	return resp, err
}

// Tokens lists tokens.
func (c *Client) Tokens() ([]TokenInfo, error) {
	var out []TokenInfo
	err := c.do("GET", "/tokens", nil, &out)
	return out, err
}

// RevokeToken deletes a token and disconnects its agents.
func (c *Client) RevokeToken(name string) (RevokeTokenResponse, error) {
	var resp RevokeTokenResponse
	err := c.do("DELETE", "/tokens/"+url.PathEscape(name), nil, &resp)
	return resp, err
}

// IssueCert issues an agent certificate for a token.
func (c *Client) IssueCert(token string, days int) (IssueCertResponse, error) {
	var resp IssueCertResponse
	err := c.do("POST", "/tokens/"+url.PathEscape(token)+"/certs", IssueCertRequest{Days: days}, &resp)
	return resp, err
}

// Reserve adds a permanent reservation.
func (c *Client) Reserve(req ReservationRequest) (ReservationInfo, error) {
	var resp ReservationInfo
	err := c.do("POST", "/reservations", req, &resp)
	return resp, err
}

// Reservations lists permanent reservations.
func (c *Client) Reservations() ([]ReservationInfo, error) {
	var out []ReservationInfo
	err := c.do("GET", "/reservations", nil, &out)
	return out, err
}

// Unreserve removes a permanent reservation.
func (c *Client) Unreserve(name string) error {
	return c.do("DELETE", "/reservations/"+url.PathEscape(name), nil, nil)
}

// AgentStatus returns an agent's status.
func (c *Client) AgentStatus() (agent.Status, error) {
	var st agent.Status
	err := c.do("GET", "/status", nil, &st)
	return st, err
}
