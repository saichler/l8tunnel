package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// poolTunnel presents a TERMINATE forward's pool to httpproxy, which then
// gives the edge HTTP/1.1 and h2, streaming, WebSockets, forwarded headers
// and a connection pool per backend.
type poolTunnel struct {
	id     string
	pool   *pool
	fwd    *tun.EdgePortForward
	access *auth.Access
}

func (t *poolTunnel) ID() string { return t.id }

func (t *poolTunnel) Access() *auth.Access { return t.access }

// OpenStream picks and dials a backend; https backends are dialed with TLS
// (certificates verified unless the forward sets skip_verify).
func (t *poolTunnel) OpenStream(ctx context.Context, clientAddr string) (net.Conn, error) {
	return t.secure(ctx, func() (net.Conn, *member, error) { return t.pool.dial(ctx, clientIP(clientAddr)) })
}

// Pick implements httpproxy.Balancer: the proxy balances each request and
// keeps a connection pool per member.
func (t *poolTunnel) Pick(clientAddr string) (string, error) {
	m := t.pool.pick(clientIP(clientAddr), nil)
	if m == nil {
		return "", fmt.Errorf("%w: %s", httpproxy.ErrUnavailable, t.id)
	}
	return m.addr, nil
}

// OpenStreamTo implements httpproxy.Balancer. When the picked member
// refuses the dial another one is used (it has just failed, so this is
// rare), and that connection may serve later requests of the pick's pool.
func (t *poolTunnel) OpenStreamTo(ctx context.Context, backend string) (net.Conn, error) {
	return t.secure(ctx, func() (net.Conn, *member, error) { return t.pool.dialAddr(ctx, backend) })
}

func (t *poolTunnel) secure(ctx context.Context, dial func() (net.Conn, *member, error)) (net.Conn, error) {
	conn, m, err := dial()
	if errors.Is(err, ErrNoHealthyMember) {
		return nil, fmt.Errorf("%w: %s", httpproxy.ErrUnavailable, t.id)
	}
	if err != nil {
		return nil, err
	}
	if t.fwd.BackendScheme == tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTP {
		return conn, nil
	}
	tconn := tls.Client(conn, &tls.Config{ServerName: m.host, InsecureSkipVerify: t.fwd.SkipVerify,
		NextProtos: []string{"http/1.1"}})
	if err := tconn.HandshakeContext(ctx); err != nil {
		conn.Close()
		m.failed("TLS: " + err.Error())
		return nil, err
	}
	return tconn, nil
}
