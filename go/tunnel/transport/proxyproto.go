package transport

import (
	"errors"
	"net"
	"net/netip"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
)

// proxyHeaderTimeout bounds how long a trusted proxy may take to send its
// PROXY header.
const proxyHeaderTimeout = 10 * time.Second

// ProxyProtocolListener reads PROXY protocol (v1 or v2) headers on
// connections from trusted networks, so RemoteAddr returns the original
// client's address. A header from any other address is refused, so a
// client can't spoof its address. A connection from a trusted network
// without a header keeps its own address. With no trusted networks, ln is
// returned unchanged.
func ProxyProtocolListener(ln net.Listener, trusted []netip.Prefix) net.Listener {
	if len(trusted) == 0 {
		return ln
	}
	return &proxiedListener{Listener: &proxyproto.Listener{
		Listener:          ln,
		ReadHeaderTimeout: proxyHeaderTimeout,
		ConnPolicy: func(opts proxyproto.ConnPolicyOptions) (proxyproto.Policy, error) {
			if IsTrusted(opts.Upstream, trusted) {
				return proxyproto.USE, nil
			}
			return proxyproto.REJECT, nil
		},
	}}
}

// proxiedListener hands out connections that can be half-closed, which
// the relay's copy loop (pipe.Join) needs.
type proxiedListener struct {
	net.Listener
}

func (l *proxiedListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	if pc, ok := conn.(*proxyproto.Conn); ok {
		return &ProxiedConn{Conn: pc}, nil
	}
	return conn, nil
}

// ProxiedConn is a connection that arrived through a PROXY protocol
// listener. RemoteAddr is the original client's address.
type ProxiedConn struct {
	*proxyproto.Conn
}

// CloseWrite half-closes the underlying TCP connection.
func (c *ProxiedConn) CloseWrite() error {
	if hc, ok := c.Raw().(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return errors.ErrUnsupported
}

// IsTrusted reports whether addr's IP is in one of the networks.
func IsTrusted(addr net.Addr, trusted []netip.Prefix) bool {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}
