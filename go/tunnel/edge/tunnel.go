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
	conn, m, err := t.pool.dial(ctx, clientIP(clientAddr))
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
