package transport

import (
	"bufio"
	"context"
	"encoding/base64"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"time"
)

// ProxyNone disables proxying in DialOptions.Proxy.
const ProxyNone = "none"

// DialOptions controls how the agent reaches the relay.
type DialOptions struct {
	// Proxy is an http:// proxy URL, ProxyNone, or empty to use
	// HTTPS_PROXY / NO_PROXY from the environment.
	Proxy string
}

// ParseProxy validates a proxy setting (see DialOptions.Proxy).
func ParseProxy(s string) error {
	if s == "" || s == ProxyNone {
		return nil
	}
	_, err := parseProxyURL(s)
	return err
}

func parseProxyURL(s string) (*url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return nil, fmt.Errorf("proxy %q: %w", s, err)
	}
	if u.Scheme != "http" || u.Host == "" {
		return nil, fmt.Errorf("proxy %q must be http://host:port", s)
	}
	return u, nil
}

// proxyFor resolves the proxy for reaching addr, or nil for a direct
// connection.
func (o DialOptions) proxyFor(addr string) (*url.URL, error) {
	switch o.Proxy {
	case ProxyNone:
		return nil, nil
	case "":
		// ProxyFromEnvironment applies HTTPS_PROXY and NO_PROXY (read once
		// per process).
		u, err := http.ProxyFromEnvironment(&http.Request{URL: &url.URL{Scheme: "https", Host: addr}})
		if err != nil || u == nil {
			return nil, err
		}
		if u.Scheme != "http" {
			return nil, fmt.Errorf("proxy %s from the environment: only http:// proxies are supported", u.Redacted())
		}
		return u, nil
	}
	return parseProxyURL(o.Proxy)
}

// dialTCP connects to addr directly or through an HTTP CONNECT proxy.
func (o DialOptions) dialTCP(ctx context.Context, addr string) (net.Conn, error) {
	proxy, err := o.proxyFor(addr)
	if err != nil {
		return nil, err
	}
	d := &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	if proxy == nil {
		return d.DialContext(ctx, "tcp", addr)
	}
	conn, err := d.DialContext(ctx, "tcp", proxy.Host)
	if err != nil {
		return nil, fmt.Errorf("dial proxy %s: %w", proxy.Redacted(), err)
	}
	if err := connect(ctx, conn, proxy, addr); err != nil {
		conn.Close()
		return nil, err
	}
	return conn, nil
}

// connect asks an HTTP proxy to open a tunnel to addr.
func connect(ctx context.Context, conn net.Conn, proxy *url.URL, addr string) error {
	if deadline, ok := ctx.Deadline(); ok {
		conn.SetDeadline(deadline)
	} else {
		conn.SetDeadline(time.Now().Add(10 * time.Second))
	}
	defer conn.SetDeadline(time.Time{})

	req := &http.Request{
		Method: http.MethodConnect,
		URL:    &url.URL{Opaque: addr},
		Host:   addr,
		Header: http.Header{},
	}
	if u := proxy.User; u != nil {
		password, _ := u.Password()
		creds := base64.StdEncoding.EncodeToString([]byte(u.Username() + ":" + password))
		req.Header.Set("Proxy-Authorization", "Basic "+creds)
	}
	if err := req.Write(conn); err != nil {
		return fmt.Errorf("proxy %s: send CONNECT: %w", proxy.Redacted(), err)
	}
	// The proxy sends nothing after its response until we speak, so the
	// buffered reader can't swallow tunnel bytes.
	resp, err := http.ReadResponse(bufio.NewReader(conn), req)
	if err != nil {
		return fmt.Errorf("proxy %s: read CONNECT response: %w", proxy.Redacted(), err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxy %s refused CONNECT %s: %s", proxy.Redacted(), addr, resp.Status)
	}
	return nil
}
