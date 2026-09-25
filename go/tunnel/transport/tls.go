// Package transport builds the TLS connections and the stream multiplexer
// that carry the agent <-> relay session.
package transport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

// ServerTLSConfig loads the relay's certificate and returns a TLS 1.3-only
// config that offers the l8tunnel ALPN.
func ServerTLSConfig(certFile, keyFile string) (*tls.Config, error) {
	if certFile == "" || keyFile == "" {
		return nil, fmt.Errorf("both a TLS certificate and key file are required")
	}
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load TLS key pair %s / %s: %w", certFile, keyFile, err)
	}
	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS13,
		NextProtos:   []string{protocol.ALPN},
	}, nil
}

// ClientTLSConfig returns the agent's TLS config. serverName is verified
// against the relay's certificate. When caFile is set, only that CA is
// trusted; otherwise the system roots are used.
func ClientTLSConfig(serverName, caFile string) (*tls.Config, error) {
	if serverName == "" {
		return nil, fmt.Errorf("a TLS server name is required")
	}
	cfg := &tls.Config{
		ServerName: serverName,
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{protocol.ALPN},
	}
	if caFile != "" {
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read CA file: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("CA file %s contains no PEM certificates", caFile)
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// DialRelay opens a TLS connection to the relay and checks that the
// l8tunnel ALPN was negotiated.
func DialRelay(ctx context.Context, addr string, cfg *tls.Config) (*tls.Conn, error) {
	dialer := &tls.Dialer{
		NetDialer: &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
		Config:    cfg,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("dial relay %s: %w", addr, err)
	}
	tlsConn := conn.(*tls.Conn)
	if err := CheckALPN(tlsConn); err != nil {
		tlsConn.Close()
		return nil, err
	}
	return tlsConn, nil
}

// CheckALPN verifies that a completed handshake negotiated the l8tunnel ALPN.
func CheckALPN(conn *tls.Conn) error {
	got := conn.ConnectionState().NegotiatedProtocol
	if got != protocol.ALPN {
		return fmt.Errorf("peer negotiated ALPN %q, want %q", got, protocol.ALPN)
	}
	return nil
}
