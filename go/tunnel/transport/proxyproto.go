package transport

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
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

// l8tunnel's own PROXY v2 TLV types (0xE0-0xEF is the custom range).
const (
	// TLVTunnel names the tunnel a stream on a relay's stream port is for.
	TLVTunnel proxyproto.PP2Type = 0xE0
	// TLVAuth proves a relay or the edge sent the header: an 8-byte Unix
	// time followed by an HMAC-SHA256 over the time, the tunnel name (or
	// host) and the client address, keyed with the cluster secret.
	TLVAuth proxyproto.PP2Type = 0xE1
)

// streamAuthWindow bounds the clock skew (and replay window) of TLVAuth.
const streamAuthWindow = time.Minute

// WriteProxyHeader writes a PROXY v2 header for a connection from src to
// dst, carrying the given TLVs.
func WriteProxyHeader(w io.Writer, src, dst net.Addr, tlvs ...proxyproto.TLV) error {
	h := proxyproto.HeaderProxyFromAddrs(2, src, dst)
	if len(tlvs) > 0 {
		if err := h.SetTLVs(tlvs); err != nil {
			return err
		}
	}
	_, err := h.WriteTo(w)
	return err
}

// ProxyTLVs returns the TLVs of the PROXY header a connection arrived
// with, or nil.
func ProxyTLVs(conn net.Conn) []proxyproto.TLV {
	for {
		switch c := conn.(type) {
		case *ProxiedConn:
			if h := c.ProxyHeader(); h != nil {
				tlvs, err := h.TLVs()
				if err == nil {
					return tlvs
				}
			}
			return nil
		case interface{ NetConn() net.Conn }:
			conn = c.NetConn()
		default:
			return nil
		}
	}
}

// FindTLV returns the value of the first TLV of type t.
func FindTLV(tlvs []proxyproto.TLV, t proxyproto.PP2Type) ([]byte, bool) {
	for _, tlv := range tlvs {
		if tlv.Type == t {
			return tlv.Value, true
		}
	}
	return nil, false
}

// SignedTLVs are the name and auth TLVs for a stream to tunnel (or for a
// forwarded connection to host) from client.
func SignedTLVs(key []byte, subject, client string, now time.Time) []proxyproto.TLV {
	return []proxyproto.TLV{
		{Type: TLVTunnel, Value: []byte(subject)},
		{Type: TLVAuth, Value: signStream(key, subject, client, now.Unix())},
	}
}

// VerifySignedTLVs checks the auth TLV and returns the signed subject.
func VerifySignedTLVs(key []byte, tlvs []proxyproto.TLV, client string, now time.Time) (string, error) {
	subject, ok := FindTLV(tlvs, TLVTunnel)
	if !ok {
		return "", errors.New("no tunnel TLV")
	}
	auth, ok := FindTLV(tlvs, TLVAuth)
	if !ok || len(auth) != 8+sha256.Size {
		return "", errors.New("no valid auth TLV")
	}
	ts := int64(binary.BigEndian.Uint64(auth[:8]))
	if d := now.Unix() - ts; d > int64(streamAuthWindow.Seconds()) || d < -int64(streamAuthWindow.Seconds()) {
		return "", errors.New("auth TLV outside the time window")
	}
	if !hmac.Equal(auth, signStream(key, string(subject), client, ts)) {
		return "", errors.New("auth TLV doesn't verify")
	}
	return string(subject), nil
}

func signStream(key []byte, subject, client string, ts int64) []byte {
	out := make([]byte, 8, 8+sha256.Size)
	binary.BigEndian.PutUint64(out, uint64(ts))
	mac := hmac.New(sha256.New, key)
	mac.Write(out[:8])
	mac.Write([]byte(subject))
	mac.Write([]byte{0})
	mac.Write([]byte(client))
	return mac.Sum(out)
}
