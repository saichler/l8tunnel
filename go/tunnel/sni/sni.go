// Package sni reads the TLS ClientHello of a connection without consuming
// it, so the connection can then be routed by server name and ALPN: handed
// to tls.Server (termination) or forwarded as raw bytes (passthrough).
package sni

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// Conn replays the bytes already read from a connection before reading
// further from it. Writes, CloseWrite and addresses go to the underlying
// connection.
type Conn struct {
	net.Conn
	r io.Reader
}

// Read reads the replayed bytes first, then the underlying connection.
func (c *Conn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// WriteTo keeps io.Copy from reading straight from the underlying socket
// (which would skip the replayed bytes) if the embedded connection ever
// exposes a WriteTo of its own.
func (c *Conn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, struct{ io.Reader }{c.r})
}

// ReadFrom lets io.Copy use the underlying connection's fast path (splice
// on TCP) for writes, which the replay doesn't affect.
func (c *Conn) ReadFrom(r io.Reader) (int64, error) {
	if rf, ok := c.Conn.(io.ReaderFrom); ok {
		return rf.ReadFrom(r)
	}
	return io.Copy(struct{ io.Writer }{c.Conn}, r)
}

// CloseWrite half-closes the underlying connection.
func (c *Conn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return errors.ErrUnsupported
}

// Peek reads the TLS ClientHello from conn. The returned connection
// replays it, so nothing is lost for the next reader.
func Peek(conn net.Conn) (*tls.ClientHelloInfo, *Conn, error) {
	var peeked bytes.Buffer
	hello, err := readClientHello(io.TeeReader(conn, &peeked))
	if err != nil {
		return nil, nil, err
	}
	return hello, &Conn{Conn: conn, r: io.MultiReader(&peeked, conn)}, nil
}

var errHelloRead = errors.New("client hello read")

// readClientHello parses a ClientHello by starting a server handshake on a
// read-only connection and stopping it as soon as the hello is decoded.
func readClientHello(r io.Reader) (*tls.ClientHelloInfo, error) {
	var hello *tls.ClientHelloInfo
	err := tls.Server(readOnlyConn{r: r}, &tls.Config{
		GetConfigForClient: func(h *tls.ClientHelloInfo) (*tls.Config, error) {
			copied := *h
			hello = &copied
			return nil, errHelloRead
		},
	}).Handshake()
	if hello == nil {
		return nil, err
	}
	return hello, nil
}

// readOnlyConn lets tls.Server read a ClientHello; any write fails, so the
// peek never sends anything to the client.
type readOnlyConn struct {
	r io.Reader
}

func (c readOnlyConn) Read(p []byte) (int, error)     { return c.r.Read(p) }
func (readOnlyConn) Write([]byte) (int, error)        { return 0, io.ErrClosedPipe }
func (readOnlyConn) Close() error                     { return nil }
func (readOnlyConn) LocalAddr() net.Addr              { return nil }
func (readOnlyConn) RemoteAddr() net.Addr             { return nil }
func (readOnlyConn) SetDeadline(time.Time) error      { return nil }
func (readOnlyConn) SetReadDeadline(time.Time) error  { return nil }
func (readOnlyConn) SetWriteDeadline(time.Time) error { return nil }
