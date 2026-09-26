package sni

import (
	"bufio"
	"bytes"
	"errors"
	"io"
	"net"
	"net/textproto"
	"strings"
)

// maxHeaderPeek bounds how much of an HTTP request is read to find Host.
const maxHeaderPeek = 16 << 10

// PeekHTTPHost reads an HTTP/1.x request's header block and returns its
// Host (lowercase, without the port). The returned connection replays
// everything read.
func PeekHTTPHost(conn net.Conn) (string, *Conn, error) {
	var peeked bytes.Buffer
	r := bufio.NewReaderSize(io.TeeReader(io.LimitReader(conn, maxHeaderPeek), &peeked), 4096)
	tp := textproto.NewReader(r)
	if _, err := tp.ReadLine(); err != nil {
		return "", nil, err
	}
	hdr, err := tp.ReadMIMEHeader()
	if err != nil {
		return "", nil, err
	}
	host := hdr.Get("Host")
	if host == "" {
		return "", nil, errors.New("no Host header")
	}
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	// bufio may have read past the header block; the tee kept all of it.
	return strings.ToLower(host), &Conn{Conn: conn, r: io.MultiReader(&peeked, conn)}, nil
}
