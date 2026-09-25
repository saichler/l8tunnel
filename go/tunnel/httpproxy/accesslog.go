package httpproxy

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"time"
)

// logRequests wraps next with an access log line per request.
func (p *Proxy) logRequests(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &recorder{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(rec, r)
		p.log.Info("http request", "host", r.Host, "method", r.Method, "path", r.URL.Path,
			"proto", r.Proto, "status", rec.status, "bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(), "client", r.RemoteAddr,
			"user_agent", r.UserAgent(), "error", rec.Header().Get(ErrorHeader))
	})
}

// recorder captures the status and size of a response. It keeps
// streaming (Flush) and protocol upgrades (Hijack) working.
type recorder struct {
	http.ResponseWriter
	status int
	bytes  int64
}

func (r *recorder) WriteHeader(status int) {
	r.status = status
	r.ResponseWriter.WriteHeader(status)
}

func (r *recorder) Write(p []byte) (int, error) {
	n, err := r.ResponseWriter.Write(p)
	r.bytes += int64(n)
	return n, err
}

func (r *recorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *recorder) Hijack() (net.Conn, *bufio.ReadWriter, error) {
	h, ok := r.ResponseWriter.(http.Hijacker)
	if !ok {
		return nil, nil, fmt.Errorf("response writer can't be hijacked")
	}
	r.status = http.StatusSwitchingProtocols
	return h.Hijack()
}

// Unwrap lets http.ResponseController reach the underlying writer.
func (r *recorder) Unwrap() http.ResponseWriter {
	return r.ResponseWriter
}
