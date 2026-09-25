package relay

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"time"
)

// prefixConn replays bytes already read from a TCP connection before
// reading further from it. Writes and CloseWrite go to the TCP connection.
type prefixConn struct {
	*net.TCPConn
	r io.Reader
}

func (c *prefixConn) Read(p []byte) (int, error) {
	return c.r.Read(p)
}

// WriteTo overrides the embedded TCPConn's WriteTo, which io.Copy would
// otherwise use to read straight from the socket, skipping the replayed
// bytes.
func (c *prefixConn) WriteTo(w io.Writer) (int64, error) {
	return io.Copy(w, struct{ io.Reader }{c.r})
}

// peekClientHello reads the TLS ClientHello from conn without consuming
// it: the returned connection replays the hello, so it can be handed to
// tls.Server (termination) or forwarded as raw bytes (passthrough).
func peekClientHello(conn *net.TCPConn) (*tls.ClientHelloInfo, *prefixConn, error) {
	var peeked bytes.Buffer
	hello, err := readClientHello(io.TeeReader(conn, &peeked))
	if err != nil {
		return nil, nil, err
	}
	return hello, &prefixConn{TCPConn: conn, r: io.MultiReader(&peeked, conn)}, nil
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
