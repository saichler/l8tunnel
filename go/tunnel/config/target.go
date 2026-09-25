package config

import (
	"fmt"
	"net"
	"net/url"
	"strconv"
)

// parseTarget parses a tunnel target: "8080" (127.0.0.1:8080),
// "host:port", "http://host[:port]" or "https://host[:port]". useTLS is
// true for https targets. An empty target stays empty (ssh's default).
func parseTarget(s string) (hostport string, useTLS bool, err error) {
	if s == "" {
		return "", false, nil
	}
	if p, err := strconv.Atoi(s); err == nil {
		if p < 1 || p > 65535 {
			return "", false, fmt.Errorf("target port %d is not a valid port", p)
		}
		return net.JoinHostPort("127.0.0.1", s), false, nil
	}
	u, err := url.Parse(s)
	if err == nil && (u.Scheme == "http" || u.Scheme == "https") {
		if u.Path != "" && u.Path != "/" || u.RawQuery != "" || u.User != nil {
			return "", false, fmt.Errorf("target %q: only scheme, host and port are allowed", s)
		}
		host, port := u.Hostname(), u.Port()
		if host == "" {
			return "", false, fmt.Errorf("target %q has no host", s)
		}
		if port == "" {
			port = map[string]string{"http": "80", "https": "443"}[u.Scheme]
		}
		return net.JoinHostPort(host, port), u.Scheme == "https", nil
	}
	if _, _, err := net.SplitHostPort(s); err != nil {
		return "", false, fmt.Errorf("target %q must be a port, host:port or http(s)://host:port", s)
	}
	return s, false, nil
}
