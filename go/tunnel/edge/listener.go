package edge

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/httpproxy"
	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/sni"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/tun"
)

const peekTimeout = 10 * time.Second

// listener is one public port.
type listener struct {
	edge   *Edge
	port   int
	proto  tun.EdgeProtocol
	ln     net.Listener
	err    error // bind error, reported in the status
	routes atomic.Pointer[routeSet]

	httpOnce sync.Once
	http     *httpproxy.Proxy
}

// listen binds a port; a failure is kept for the status, not fatal.
func (e *Edge) listen(port int, proto tun.EdgeProtocol) *listener {
	l := &listener{edge: e, port: port, proto: proto}
	ln, err := net.Listen("tcp", net.JoinHostPort(e.cfg.BindHost, strconv.Itoa(port)))
	if err != nil {
		l.err = err
		e.log.Warn("edge: can't listen", "port", port, "error", err)
		return l
	}
	l.ln = ln
	go l.accept()
	return l
}

func (l *listener) setRoutes(rs *routeSet) { l.routes.Store(rs) }

func (l *listener) close() {
	if l.ln != nil {
		l.ln.Close()
	}
	if l.http != nil {
		l.http.Close()
	}
}

func (l *listener) accept() {
	for {
		conn, err := l.ln.Accept()
		if err != nil {
			if errors.Is(err, net.ErrClosed) {
				return
			}
			time.Sleep(100 * time.Millisecond)
			continue
		}
		e := l.edge
		if !e.limiter.Allow(clientIP(conn.RemoteAddr().String())) {
			e.counters.rejectedRate.Add(1)
			conn.Close()
			continue
		}
		e.counters.accepted.Add(1)
		go l.serve(conn.(*net.TCPConn))
	}
}

func (l *listener) serve(raw *net.TCPConn) {
	rs := l.routes.Load()
	switch l.proto {
	case tun.EdgeProtocol_EDGE_PROTOCOL_TLS:
		l.serveTLS(raw, rs)
	case tun.EdgeProtocol_EDGE_PROTOCOL_HTTP:
		l.serveHTTP(raw, rs)
	default:
		l.serveTCP(raw, rs)
	}
}

func (l *listener) serveTLS(raw *net.TCPConn, rs *routeSet) {
	raw.SetReadDeadline(time.Now().Add(peekTimeout))
	hello, conn, err := sni.Peek(raw)
	if err != nil {
		raw.Close()
		return
	}
	t := rs.resolve(hello.ServerName)
	if !l.admitted(t, raw) {
		reject(conn)
		return
	}
	if t.route.fwd.Mode == tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE {
		l.terminate(conn)
		return
	}
	raw.SetReadDeadline(time.Time{})
	l.forward(conn, raw, t)
}

func (l *listener) serveHTTP(raw *net.TCPConn, rs *routeSet) {
	raw.SetReadDeadline(time.Now().Add(peekTimeout))
	host, conn, err := sni.PeekHTTPHost(raw)
	if err != nil {
		raw.Close()
		return
	}
	t := rs.resolve(host)
	if !l.admitted(t, raw) {
		conn.Write([]byte("HTTP/1.1 404 Not Found\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"))
		conn.Close()
		return
	}
	raw.SetReadDeadline(time.Time{})
	l.forward(conn, raw, t)
}

func (l *listener) serveTCP(raw *net.TCPConn, rs *routeSet) {
	if rs.single == nil {
		raw.Close()
		return
	}
	t := target{route: rs.single, ok: true}
	if t.route.isRelay() {
		if t.route.fwd.ListenPortEnd != 0 {
			l.stream(raw, t.route)
			return
		}
		t.relay, t.ok = l.edge.relayPick(false)
	}
	if !l.admitted(t, raw) {
		raw.Close()
		return
	}
	l.forward(raw, raw, t)
}

// admitted checks the route exists and the domain's IP lists allow the
// client.
func (l *listener) admitted(t target, raw net.Conn) bool {
	e := l.edge
	if !t.ok || t.route == nil {
		e.counters.noRoute.Add(1)
		return false
	}
	if !t.route.access.AllowsIP(clientIP(raw.RemoteAddr().String())) {
		e.counters.rejectedIP.Add(1)
		return false
	}
	return true
}

// forward carries a connection to its relay or backend, with a PROXY
// header where the target expects one.
func (l *listener) forward(conn pipe.Conn, raw net.Conn, t target) {
	e := l.edge
	var up net.Conn
	var err error
	proxyHeader := t.route.fwd.ProxyProtocol
	if t.route.isRelay() {
		up, err = net.DialTimeout("tcp", net.JoinHostPort(t.relay.IP, strconv.Itoa(int(t.route.fwd.TargetPort))), dialTimeout)
		proxyHeader = true
	} else {
		up, _, err = t.route.pool.dial(context.Background(), clientIP(raw.RemoteAddr().String()))
	}
	if err != nil {
		e.counters.dialFailures.Add(1)
		conn.Close()
		return
	}
	if proxyHeader {
		if err := transport.WriteProxyHeader(up, raw.RemoteAddr(), raw.LocalAddr()); err != nil {
			up.Close()
			conn.Close()
			return
		}
	}
	pipe.Join(conn, up.(pipe.Conn))
}

// stream carries a mode A connection to the relay holding the port's
// tunnel, naming the tunnel in a signed PROXY header.
func (l *listener) stream(raw *net.TCPConn, r *route) {
	e := l.edge
	relay, name, ok := e.cfg.Live.OwnerOfPort(l.port)
	if !ok || !r.access.AllowsIP(clientIP(raw.RemoteAddr().String())) {
		e.counters.noRoute.Add(1)
		raw.Close()
		return
	}
	up, err := net.DialTimeout("tcp", net.JoinHostPort(relay.IP, strconv.Itoa(int(r.fwd.TargetPort))), dialTimeout)
	if err != nil {
		e.counters.dialFailures.Add(1)
		raw.Close()
		return
	}
	client := raw.RemoteAddr()
	tlvs := transport.SignedTLVs(e.cfg.ForwardKey, name, client.String(), time.Now())
	if err := transport.WriteProxyHeader(up, client, raw.LocalAddr(), tlvs...); err != nil {
		up.Close()
		raw.Close()
		return
	}
	pipe.Join(raw, up.(*net.TCPConn))
}

// terminate completes TLS with the site's certificate and serves HTTP.
func (l *listener) terminate(conn *sni.Conn) {
	l.httpOnce.Do(func() {
		l.http = httpproxy.New(httpproxy.Config{ForwardedHeaders: true, Lookup: l.lookupHTTP, Logger: l.edge.log})
	})
	tconn := tls.Server(conn, &tls.Config{GetCertificate: l.edge.cfg.Certs.GetCertificate,
		NextProtos: []string{"h2", "http/1.1"}, MinVersion: tls.VersionTLS12})
	ctx, cancel := context.WithTimeout(context.Background(), peekTimeout)
	err := tconn.HandshakeContext(ctx)
	cancel()
	if err != nil {
		conn.Close()
		return
	}
	conn.SetReadDeadline(time.Time{})
	l.http.ServeConn(tconn)
}

// lookupHTTP finds the TERMINATE forward serving a Host on this port.
func (l *listener) lookupHTTP(host string) (httpproxy.Tunnel, httpproxy.State, string) {
	t := l.routes.Load().resolve(host)
	if !t.ok || t.route.tunnel == nil {
		return nil, httpproxy.StateUnknown, ""
	}
	return t.route.tunnel, httpproxy.StateActive, t.route.domain.Domain
}

// reject fails the TLS handshake with an alert.
func reject(conn net.Conn) {
	ctx, cancel := context.WithTimeout(context.Background(), peekTimeout)
	defer cancel()
	tls.Server(conn, &tls.Config{GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return nil, errors.New("no route")
	}}).HandshakeContext(ctx)
	conn.Close()
}
