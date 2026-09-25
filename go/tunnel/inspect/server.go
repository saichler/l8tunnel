package inspect

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"strconv"
	"strings"
)

//go:embed ui.html
var uiHTML []byte

// ReplayHeader must be sent with replay requests. Browsers can't add it to
// a cross-site request without a CORS preflight, which the inspector never
// answers, so other web pages can't trigger replays.
const ReplayHeader = "X-L8tunnel-Inspector"

// CheckListenAddr refuses non-loopback addresses unless public is set:
// the inspector shows request bodies, which can hold secrets.
func CheckListenAddr(addr string, public bool) error {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		return fmt.Errorf("inspect address %q: %w", addr, err)
	}
	if public || host == "localhost" {
		return nil
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return nil
	}
	return fmt.Errorf("inspect address %s is not a loopback address; set inspect_public to expose request contents", addr)
}

// Handler serves the inspector UI and API. dial connects to a tunnel's
// local target (for replays). With localOnly, requests whose Host isn't a
// loopback name are refused, which defeats DNS rebinding.
func (r *Recorder) Handler(dial func(tunnel string) (net.Conn, error), localOnly bool) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
		w.Write(uiHTML)
	})
	mux.HandleFunc("GET /api/requests", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, r.List())
	})
	mux.HandleFunc("GET /api/requests/{id}", func(w http.ResponseWriter, req *http.Request) {
		id, _ := strconv.ParseInt(req.PathValue("id"), 10, 64)
		if e := r.Get(id); e != nil {
			writeJSON(w, http.StatusOK, e)
			return
		}
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "no such request"})
	})
	mux.HandleFunc("POST /api/requests/{id}/replay", func(w http.ResponseWriter, req *http.Request) {
		if req.Header.Get(ReplayHeader) == "" {
			writeJSON(w, http.StatusForbidden, map[string]string{"error": "missing " + ReplayHeader + " header"})
			return
		}
		id, _ := strconv.ParseInt(req.PathValue("id"), 10, 64)
		e, err := r.Replay(id, dial)
		if err != nil {
			writeJSON(w, http.StatusBadRequest, map[string]string{"error": err.Error()})
			return
		}
		writeJSON(w, http.StatusOK, e)
	})
	mux.HandleFunc("GET /api/events", func(w http.ResponseWriter, req *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-store")
		ch := r.subscribe()
		defer r.unsubscribe(ch)
		fmt.Fprint(w, ": connected\n\n")
		flusher.Flush()
		for {
			select {
			case <-req.Context().Done():
				return
			case s := <-ch:
				data, _ := json.Marshal(s)
				fmt.Fprintf(w, "data: %s\n\n", data)
				flusher.Flush()
			}
		}
	})
	if !localOnly {
		return mux
	}
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		host := req.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		host = strings.Trim(host, "[]")
		ip := net.ParseIP(host)
		if host != "localhost" && (ip == nil || !ip.IsLoopback()) {
			http.Error(w, "the inspector only answers requests for localhost", http.StatusForbidden)
			return
		}
		mux.ServeHTTP(w, req)
	})
}

func writeJSON(w http.ResponseWriter, status int, v interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}
