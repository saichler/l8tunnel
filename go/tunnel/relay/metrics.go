package relay

import (
	"fmt"
	"io"
	"net/http"
	"sort"
	"strings"
	"sync/atomic"
)

// counters are the relay-wide event counters exported as metrics.
type counters struct {
	authFailures     atomic.Int64 // bad agent tokens and access tokens
	rejectedRate     atomic.Int64 // connections over the per-IP rate limit
	rejectedIP       atomic.Int64 // connections refused by a tunnel's IP lists
	rejectedNoRoute  atomic.Int64 // TLS handshakes for no known route
	sessionsAccepted atomic.Int64 // agent sessions that completed the handshake
}

// MetricsHandler serves Prometheus metrics (text exposition format),
// computed from the relay's state at scrape time.
func (s *Server) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		s.writeMetrics(w)
	})
}

func (s *Server) writeMetrics(w io.Writer) {
	st := s.Status()
	m := &metricWriter{w: w}

	m.family("l8tunnel_build_info", "gauge", "Relay build information.")
	m.sample("l8tunnel_build_info", labels("version", s.cfg.Version), 1)

	m.family("l8tunnel_agents_connected", "gauge", "Connected agent sessions.")
	m.sample("l8tunnel_agents_connected", "", float64(len(st.Sessions)))

	m.family("l8tunnel_agent_sessions_total", "counter", "Agent sessions that completed the handshake.")
	m.sample("l8tunnel_agent_sessions_total", "", float64(s.counters.sessionsAccepted.Load()))

	m.family("l8tunnel_agent_rtt_seconds", "gauge", "Heartbeat round trip last reported by each agent.")
	for _, sess := range st.Sessions {
		m.sample("l8tunnel_agent_rtt_seconds", labels("token", sess.Token, "agent", sess.AgentID), float64(sess.RTTMicros)/1e6)
	}

	byType := map[string]int{}
	for _, sess := range st.Sessions {
		for _, t := range sess.Tunnels {
			byType[t.Type]++
		}
	}
	m.family("l8tunnel_tunnels", "gauge", "Active tunnels by type.")
	for _, typ := range []string{"tcp", "ssh", "http", "tls"} {
		m.sample("l8tunnel_tunnels", labels("type", typ), float64(byType[typ]))
	}
	m.family("l8tunnel_tunnels_parked", "gauge", "Reserved tunnel names without a connected agent.")
	m.sample("l8tunnel_tunnels_parked", "", float64(len(st.Parked)))

	perTunnel := []struct {
		name, kind, help string
		value            func(TunnelStatus) int64
	}{
		{"l8tunnel_tunnel_connections_active", "gauge", "Open streams (connections) per tunnel.", func(t TunnelStatus) int64 { return t.ActiveConns }},
		{"l8tunnel_tunnel_connections_total", "counter", "Streams opened per tunnel since it registered.", func(t TunnelStatus) int64 { return t.TotalConns }},
		{"l8tunnel_tunnel_bytes_in_total", "counter", "Bytes from clients to the service per tunnel.", func(t TunnelStatus) int64 { return t.BytesIn }},
		{"l8tunnel_tunnel_bytes_out_total", "counter", "Bytes from the service to clients per tunnel.", func(t TunnelStatus) int64 { return t.BytesOut }},
	}
	for _, metric := range perTunnel {
		m.family(metric.name, metric.kind, metric.help)
		for _, sess := range st.Sessions {
			for _, t := range sess.Tunnels {
				m.sample(metric.name, labels("tunnel", t.Name, "type", t.Type, "token", sess.Token), float64(metric.value(t)))
			}
		}
	}

	m.family("l8tunnel_auth_failures_total", "counter", "Rejected agent tokens and access tokens.")
	m.sample("l8tunnel_auth_failures_total", "", float64(s.counters.authFailures.Load()))
	m.family("l8tunnel_connections_rejected_total", "counter", "Connections refused before reaching a tunnel.")
	m.sample("l8tunnel_connections_rejected_total", labels("reason", "rate_limit"), float64(s.counters.rejectedRate.Load()))
	m.sample("l8tunnel_connections_rejected_total", labels("reason", "ip_denied"), float64(s.counters.rejectedIP.Load()))
	m.sample("l8tunnel_connections_rejected_total", labels("reason", "no_route"), float64(s.counters.rejectedNoRoute.Load()))
}

// metricWriter writes the Prometheus text format.
type metricWriter struct {
	w io.Writer
}

func (m *metricWriter) family(name, kind, help string) {
	fmt.Fprintf(m.w, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, kind)
}

func (m *metricWriter) sample(name, labels string, value float64) {
	fmt.Fprintf(m.w, "%s%s %g\n", name, labels, value)
}

// labels formats name/value pairs as {a="1",b="2"}, sorted by name.
func labels(pairs ...string) string {
	type pair struct{ k, v string }
	var ps []pair
	for i := 0; i+1 < len(pairs); i += 2 {
		ps = append(ps, pair{pairs[i], pairs[i+1]})
	}
	sort.Slice(ps, func(i, j int) bool { return ps[i].k < ps[j].k })
	parts := make([]string, 0, len(ps))
	for _, p := range ps {
		parts = append(parts, p.k+`="`+escapeLabel(p.v)+`"`)
	}
	return "{" + strings.Join(parts, ",") + "}"
}

var labelEscaper = strings.NewReplacer(`\`, `\\`, `"`, `\"`, "\n", `\n`)

func escapeLabel(v string) string {
	return labelEscaper.Replace(v)
}
