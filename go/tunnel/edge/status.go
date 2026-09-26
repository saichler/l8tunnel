package edge

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/saichler/l8tunnel/go/types/tun"
)

// Status is what the edge reports as its EdgeNode record.
type Status struct {
	Version   int64 // the domain configuration version applied
	Listeners []*tun.EdgeListenerStatus
	Backends  []*tun.EdgeBackendStatus
	Accepted  int64
}

// Status snapshots listeners and backend health. Consecutive ports of one
// range are reported as one listener.
func (e *Edge) Status() Status {
	e.mu.Lock()
	defer e.mu.Unlock()
	st := Status{Version: e.version, Accepted: e.counters.accepted.Load()}
	ports := make([]int, 0, len(e.listeners))
	for p := range e.listeners {
		ports = append(ports, p)
	}
	sort.Ints(ports)
	for _, p := range ports {
		l := e.listeners[p]
		rs := l.routes.Load()
		domains := routeDomains(rs)
		ls := &tun.EdgeListenerStatus{Port: int32(p), Protocol: l.proto, Bound: l.err == nil, Domains: domains}
		if l.err != nil {
			ls.Error = l.err.Error()
		}
		if n := len(st.Listeners); n > 0 {
			prev := st.Listeners[n-1]
			end := prev.PortEnd
			if end == 0 {
				end = prev.Port
			}
			if end == int32(p)-1 && prev.Protocol == ls.Protocol && prev.Bound && ls.Bound &&
				strings.Join(prev.Domains, ",") == strings.Join(domains, ",") {
				prev.PortEnd = int32(p)
				continue
			}
		}
		st.Listeners = append(st.Listeners, ls)
	}
	keys := make([]string, 0, len(e.pools))
	for k := range e.pools {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		p := e.pools[k]
		for _, m := range p.snapshot() {
			m.mu.Lock()
			st.Backends = append(st.Backends, &tun.EdgeBackendStatus{Domain: k, ListenPort: p.fwd.ListenPort, Target: m.addr,
				Healthy: m.healthy.Load() && !m.disabled, ActiveConns: m.active.Load(), LastError: m.lastErr,
				LastCheck: m.lastCheck.Unix()})
			m.mu.Unlock()
		}
	}
	return st
}

func routeDomains(rs *routeSet) []string {
	if rs == nil {
		return nil
	}
	seen := map[string]bool{}
	var out []string
	add := func(r *route) {
		if r != nil && !seen[r.domain.Domain] {
			seen[r.domain.Domain] = true
			out = append(out, r.domain.Domain)
		}
	}
	add(rs.base)
	add(rs.single)
	for _, r := range rs.byName {
		add(r)
	}
	for _, r := range rs.wildcards {
		add(r)
	}
	sort.Strings(out)
	return out
}

// OpsHandler serves /healthz, /readyz (listening on every configured port)
// and /metrics.
func (e *Edge) OpsHandler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) { fmt.Fprintln(w, "ok") })
	mux.HandleFunc("GET /readyz", func(w http.ResponseWriter, _ *http.Request) {
		st := e.Status()
		if len(st.Listeners) == 0 {
			w.WriteHeader(http.StatusServiceUnavailable)
			fmt.Fprintln(w, "no listeners yet")
			return
		}
		fmt.Fprintln(w, "ok")
	})
	mux.HandleFunc("GET /metrics", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		c := &e.counters
		fmt.Fprintf(w, "# TYPE l8tunnel_edge_connections_total counter\nl8tunnel_edge_connections_total %d\n", c.accepted.Load())
		fmt.Fprintf(w, "# TYPE l8tunnel_edge_rejected_total counter\n")
		fmt.Fprintf(w, "l8tunnel_edge_rejected_total{reason=\"rate_limit\"} %d\n", c.rejectedRate.Load())
		fmt.Fprintf(w, "l8tunnel_edge_rejected_total{reason=\"ip_denied\"} %d\n", c.rejectedIP.Load())
		fmt.Fprintf(w, "l8tunnel_edge_rejected_total{reason=\"no_route\"} %d\n", c.noRoute.Load())
		fmt.Fprintf(w, "# TYPE l8tunnel_edge_dial_failures_total counter\nl8tunnel_edge_dial_failures_total %d\n", c.dialFailures.Load())
		fmt.Fprintf(w, "# TYPE l8tunnel_edge_backend_up gauge\n")
		for _, b := range e.Status().Backends {
			up := 0
			if b.Healthy {
				up = 1
			}
			fmt.Fprintf(w, "l8tunnel_edge_backend_up{pool=%q,target=%q} %d\n", b.Domain, b.Target, up)
		}
	})
	return mux
}
