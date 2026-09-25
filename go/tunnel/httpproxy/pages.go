package httpproxy

import (
	"html/template"
	"net"
	"net/http"
	"strconv"
	"strings"
)

// ErrorHeader carries a machine-readable reason on every error page.
const ErrorHeader = "X-L8tunnel-Error"

type pageError struct {
	code    string
	title   string
	message string
}

var (
	errUnknownHost   = pageError{"unknown-host", "Unknown host", "This relay doesn't serve this host name."}
	errUnknownTunnel = pageError{"tunnel-not-found", "Tunnel not found", "No HTTP tunnel is registered for this host name."}
	errAgentOffline  = pageError{"agent-offline", "Tunnel offline", "The tunnel's agent is disconnected. It may be reconnecting; try again shortly."}
	errUpstream      = pageError{"upstream-error", "Service unreachable", "The tunnel's agent is connected, but the service behind it didn't answer."}
	errMisdirected   = pageError{"misdirected", "Misdirected request", "The Host header doesn't match the TLS server name of this connection."}
	errIPDenied      = pageError{"ip-denied", "Forbidden", "This tunnel doesn't accept connections from your address."}
	errUnauthorized  = pageError{"unauthorized", "Authentication required", "This tunnel requires a username and password."}
)

var pageTemplate = template.Must(template.New("page").Parse(`<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{.Status}} {{.Title}}</title>
<style>
body { font-family: system-ui, sans-serif; margin: 0; padding: 4rem 1rem; background: #f6f7f9; color: #1f2328; }
main { max-width: 36rem; margin: 0 auto; }
h1 { font-size: 1.5rem; margin: 0 0 .5rem; }
p { line-height: 1.5; }
code { background: #e8eaee; padding: .1rem .3rem; border-radius: 4px; }
footer { margin-top: 2rem; font-size: .85rem; color: #656d76; }
@media (prefers-color-scheme: dark) {
  body { background: #0d1117; color: #e6edf3; }
  code { background: #21262d; }
  footer { color: #8b949e; }
}
</style>
</head>
<body>
<main>
<h1>{{.Status}} · {{.Title}}</h1>
<p>{{.Message}}</p>
<p>Host: <code>{{.Host}}</code></p>
<footer>l8tunnel relay</footer>
</main>
</body>
</html>
`))

func writeError(w http.ResponseWriter, status int, e pageError, host string) {
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set(ErrorHeader, e.code)
	w.WriteHeader(status)
	pageTemplate.Execute(w, struct {
		Status               int
		Title, Message, Host string
	}{status, e.title, e.message, host})
}

// RedirectHandler redirects plain HTTP requests to HTTPS on the same host.
// httpsPort is the port clients use for HTTPS; 443 is left out of the URL.
func RedirectHandler(httpsPort int) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		if host == "" || strings.ContainsAny(host, "/\\") {
			http.Error(w, "missing or invalid Host header", http.StatusBadRequest)
			return
		}
		if httpsPort != 443 {
			host = net.JoinHostPort(host, strconv.Itoa(httpsPort))
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
