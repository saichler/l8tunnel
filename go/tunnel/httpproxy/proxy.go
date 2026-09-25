// Package httpproxy is termination mode for HTTP tunnels: it serves the
// TLS connections the relay has already terminated, routes each request by
// its Host header and reverse-proxies it through the tunnel's agent.
package httpproxy

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// State is the lookup result for a tunnel name.
type State int

const (
	// StateUnknown: no HTTP tunnel has this name.
	StateUnknown State = iota
	// StateOffline: the name is reserved for an HTTP tunnel whose agent is
	// disconnected (the relay's grace period).
	StateOffline
	// StateActive: the tunnel is connected and can serve requests.
	StateActive
)

// Tunnel is an active HTTP tunnel.
type Tunnel interface {
	// ID is unique per registration; the proxy caches connections by it.
	ID() string
	// OpenStream opens a byte stream to the tunnel's local service.
	OpenStream(ctx context.Context, clientAddr string) (net.Conn, error)
	// Access is the tunnel's access policy (IP lists, basic auth).
	Access() *auth.Access
}

// LookupFunc resolves a host name (lowercase, no port). The Tunnel is nil
// unless the state is StateActive. name identifies the tunnel the host
// belongs to ("" for a host the relay doesn't serve); two hosts of the
// same tunnel return the same name.
type LookupFunc func(host string) (tun Tunnel, state State, name string)

// Config configures a Proxy.
type Config struct {
	// ForwardedHeaders adds X-Forwarded-For/-Host/-Proto to proxied
	// requests. Incoming X-Forwarded-* headers are always dropped.
	ForwardedHeaders bool
	// AccessLog logs one line per request.
	AccessLog bool
	Lookup    LookupFunc
	Logger    *slog.Logger
}

// Proxy is an HTTP/1.1 and HTTP/2 server for terminated tunnel traffic.
type Proxy struct {
	cfg      Config
	log      *slog.Logger
	listener *transport.ConnListener
	server   *http.Server
	done     chan struct{}

	mu      sync.Mutex
	proxies map[string]*tunnelProxy // tunnel ID -> proxy
}

type tunnelProxy struct {
	transport *http.Transport
	proxy     *httputil.ReverseProxy
}

// New starts a Proxy. Hand it connections with ServeConn.
func New(cfg Config) *Proxy {
	p := &Proxy{
		cfg:      cfg,
		log:      cfg.Logger,
		listener: transport.NewConnListener(),
		proxies:  map[string]*tunnelProxy{},
		done:     make(chan struct{}),
	}
	var handler http.Handler = p
	if cfg.AccessLog {
		handler = p.logRequests(p)
	}
	p.server = &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 30 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(cfg.Logger.Handler(), slog.LevelDebug),
	}
	go func() {
		defer close(p.done)
		// Serve returns when Close closes the listener.
		p.server.Serve(p.listener)
	}()
	return p
}

// ServeConn serves HTTP on a TLS connection whose handshake is done. The
// proxy owns the connection from here on.
func (p *Proxy) ServeConn(conn net.Conn) {
	p.listener.Push(conn)
}

// Forget drops the cached connections of a tunnel that closed.
func (p *Proxy) Forget(tunnelID string) {
	p.mu.Lock()
	tp := p.proxies[tunnelID]
	delete(p.proxies, tunnelID)
	p.mu.Unlock()
	if tp != nil {
		tp.transport.CloseIdleConnections()
	}
}

// Close stops serving and closes every connection.
func (p *Proxy) Close() error {
	err := p.server.Close()
	<-p.done
	return err
}

// ServeHTTP routes a request by its Host header.
func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	tun, state, name := p.cfg.Lookup(normalizeHost(r.Host))
	if name == "" {
		writeError(w, http.StatusNotFound, errUnknownHost, r.Host)
		return
	}
	// The TLS certificate was chosen for the SNI name; serving a different
	// tunnel's Host on that connection would bypass per-host policy.
	if r.TLS != nil {
		if _, _, sniName := p.cfg.Lookup(normalizeHost(r.TLS.ServerName)); sniName != name {
			writeError(w, http.StatusMisdirectedRequest, errMisdirected, r.Host)
			return
		}
	}
	switch state {
	case StateActive:
		if !authorize(w, r, tun.Access()) {
			return
		}
		p.proxyFor(tun).proxy.ServeHTTP(w, r)
	case StateOffline:
		writeError(w, http.StatusBadGateway, errAgentOffline, r.Host)
	default:
		writeError(w, http.StatusNotFound, errUnknownTunnel, r.Host)
	}
}

// authorize applies a tunnel's access policy, writing the 403/401 page
// when the request isn't allowed. Credentials the relay checked are
// removed so they don't reach (or confuse) the service.
func authorize(w http.ResponseWriter, r *http.Request, access *auth.Access) bool {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil || !access.AllowsIP(ap.Addr()) {
		writeError(w, http.StatusForbidden, errIPDenied, r.Host)
		return false
	}
	if access.RequiresBasic() {
		user, password, ok := r.BasicAuth()
		if !ok || !access.CheckBasic(user, password) {
			w.Header().Set("WWW-Authenticate", `Basic realm="l8tunnel", charset="UTF-8"`)
			writeError(w, http.StatusUnauthorized, errUnauthorized, r.Host)
			return false
		}
		r.Header.Del("Authorization")
	}
	return true
}

// normalizeHost lowercases a Host header value and drops its port and
// trailing dot.
func normalizeHost(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	return strings.ToLower(strings.TrimSuffix(host, "."))
}

func (p *Proxy) proxyFor(tun Tunnel) *tunnelProxy {
	p.mu.Lock()
	defer p.mu.Unlock()
	if tp := p.proxies[tun.ID()]; tp != nil {
		return tp
	}
	tp := p.newTunnelProxy(tun)
	p.proxies[tun.ID()] = tp
	return tp
}

func (p *Proxy) newTunnelProxy(tun Tunnel) *tunnelProxy {
	transport := &http.Transport{
		// Every connection to the agent is a new stream; the address is
		// meaningless because the tunnel decides where the stream goes.
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			return tun.OpenStream(ctx, "")
		},
		MaxIdleConnsPerHost: 32,
		IdleConnTimeout:     90 * time.Second,
		// Pass the response through exactly as the service sent it.
		DisableCompression: true,
	}
	proxy := &httputil.ReverseProxy{
		Rewrite: func(pr *httputil.ProxyRequest) {
			pr.Out.URL.Scheme = "http"
			pr.Out.URL.Host = pr.In.Host
			pr.Out.Host = pr.In.Host
			if p.cfg.ForwardedHeaders {
				pr.SetXForwarded()
			}
		},
		Transport: transport,
		// Flush immediately so server-sent events and long polling work.
		FlushInterval: -1,
		ErrorLog:      slog.NewLogLogger(p.log.Handler(), slog.LevelDebug),
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			p.log.Warn("proxying to tunnel failed", "host", r.Host, "error", err)
			writeError(w, http.StatusBadGateway, errUpstream, r.Host)
		},
	}
	return &tunnelProxy{transport: transport, proxy: proxy}
}
