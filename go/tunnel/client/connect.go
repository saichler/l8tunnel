// Package client implements the accessing side of mode B: reaching a
// TCP/SSH tunnel through the relay's TLS port by SNI.
package client

import (
	"context"
	"fmt"
	"io"
	"net"
	"strings"

	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// Config configures Connect.
type Config struct {
	// Host is the tunnel host name, <name>.<base-domain>. It is sent as
	// the TLS SNI and verified against the relay's certificate.
	Host string
	// RelayAddr is the relay's TLS address; empty means Host:443, since the
	// tunnel host name resolves to the relay.
	RelayAddr string
	// CAFile is a CA to trust for the relay; empty means system roots.
	CAFile string
}

// Connect opens a TLS connection to the tunnel and copies in to it and it
// to out. It returns when the relay side is done, which is what an
// OpenSSH ProxyCommand needs: when the remote end closes, the command must
// exit even if its stdin is still open.
func Connect(ctx context.Context, cfg Config, in io.Reader, out io.Writer) error {
	host := strings.ToLower(strings.TrimSuffix(cfg.Host, "."))
	if host == "" {
		return fmt.Errorf("a tunnel host name is required")
	}
	addr := cfg.RelayAddr
	if addr == "" {
		addr = net.JoinHostPort(host, "443")
	}
	tlsCfg, err := transport.TunnelClientTLSConfig(host, cfg.CAFile)
	if err != nil {
		return err
	}
	conn, err := transport.Dial(ctx, addr, tlsCfg)
	if err != nil {
		return fmt.Errorf("tunnel %s: %w", host, err)
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	go func() {
		// Half-close once the local side is done sending; the relay passes
		// the EOF through to the target.
		if _, err := io.Copy(conn, in); err == nil {
			conn.CloseWrite()
		}
	}()
	if _, err := io.Copy(out, conn); err != nil && ctx.Err() == nil {
		return fmt.Errorf("tunnel %s: %w", host, err)
	}
	return ctx.Err()
}
