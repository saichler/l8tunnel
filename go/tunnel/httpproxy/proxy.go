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
	"strings"
	"sync"
	"time"
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
}

// LookupFunc resolves a tunnel name. The Tunnel is nil unless the state is
// StateActive.
type LookupFunc func(name string) (Tunnel, State)

// Config configures a Proxy.
type Config struct {
	// BaseDomain: tunnel "app" is served for Host app.<BaseDomain>.
	BaseDomain string
	// ForwardedHeaders adds X-Forwarded-For/-Host/-Proto to proxied
	// requests. Incoming X-Forwarded-* headers are always dropped.
	ForwardedHeaders bool
	Lookup           LookupFunc
	Logger           *slog.Logger
}

// Proxy is an HTTP/1.1 and HTTP/2 server for terminated tunnel traffic.
type Proxy struct {
	cfg      Config
	log      *slog.Logger
	listener *connListener
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
	cfg.BaseDomain = strings.ToLower(cfg.BaseDomain)
	p := &Proxy{
		cfg:      cfg,
		log:      cfg.Logger,
		listener: newConnListener(),
		proxies:  map[string]*tunnelProxy{},
		done:     make(chan struct{}),
	}
	p.server = &http.Server{
		Handler:           p,
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
	p.listener.push(conn)
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
	name := p.tunnelName(r.Host)
	if name == "" {
		writeError(w, http.StatusNotFound, errUnknownHost, r.Host)
		return
	}
	// The TLS certificate was chosen for the SNI name; serving a different
	// tunnel's Host on that connection would bypass per-host policy.
	if r.TLS != nil && p.tunnelName(r.TLS.ServerName) != name {
		writeError(w, http.StatusMisdirectedRequest, errMisdirected, r.Host)
		return
	}
	tun, state := p.cfg.Lookup(name)
	switch state {
	case StateActive:
		p.proxyFor(tun).proxy.ServeHTTP(w, r)
	case StateOffline:
		writeError(w, http.StatusBadGateway, errAgentOffline, r.Host)
	default:
		writeError(w, http.StatusNotFound, errUnknownTunnel, r.Host)
	}
}

// tunnelName returns the tunnel name of <name>.<base-domain>[:port], or ""
// for any other host.
func (p *Proxy) tunnelName(host string) string {
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.ToLower(strings.TrimSuffix(host, "."))
	name, ok := strings.CutSuffix(host, "."+p.cfg.BaseDomain)
	if !ok || name == "" || strings.Contains(name, ".") {
		return ""
	}
	return name
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
