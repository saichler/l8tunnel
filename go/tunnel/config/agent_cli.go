package config

import (
	"flag"
	"fmt"
	"io"
	"strings"
)

// AgentUsage describes the agent's command line.
const AgentUsage = `usage:
  l8tunnel-agent --config <agent.yaml>
  l8tunnel-agent status [--socket path] [--json]
  l8tunnel-agent [global flags] http <port|host:port|http(s)://host:port> [--name N] [--insecure-skip-verify]
  l8tunnel-agent [global flags] tls <port|host:port> [--name N]
  l8tunnel-agent [global flags] tcp <port|host:port> [--name N] [--port P]
  l8tunnel-agent [global flags] ssh [port|host:port] [--name N] [--port P]

global flags:
  --relay host:port   relay control address, e.g. connect.tunnel.example.com:443
  --server-name name  TLS server name of the relay (default: host of --relay)
  --ca file           CA certificate to trust for the relay (default: system roots)
  --token token       agent token (default: $L8TUNNEL_TOKEN)
  --cert f --key f    client certificate from "l8tunnel-server agent-cert issue"
  --status-socket p   serve "l8tunnel-agent status" on this Unix socket
  --transport t       tls (default) or wss (WebSocket, for HTTP-only networks)
  --proxy url         http://proxy:port, "none", or default HTTPS_PROXY/NO_PROXY
  --log-format f      text (default) or json
  --log-level l       debug, info (default), warn or error

tunnel flags:
  --name N                 tunnel name (default: assigned by the relay)
  --port P                 fixed public port on the relay, tcp/ssh only (default: allocated)
  --insecure-skip-verify   don't verify an https target's certificate (self-signed local services)
  --allow-ip A             only these client addresses/CIDRs may connect (repeatable)
  --deny-ip A              these client addresses/CIDRs may not connect (repeatable)
  --basic-auth user:hash   require HTTP basic auth, http only (repeatable; hash from
                           "l8tunnel hash-password")
  --access-token T         mode B clients must present T (tcp/ssh only; no mode A port)

A bare port as the target means 127.0.0.1:<port>. ssh defaults to 127.0.0.1:22.
http tunnels are served at https://<name>.<base-domain>; an https:// target makes
the agent speak TLS to the local service. tls tunnels pass the client's TLS
through untouched to a service that holds its own certificate.
`

// ParseAgentArgs parses the agent's command line (without the program
// name). With --config the file is loaded and no tunnel may be given on
// the command line; otherwise one tunnel is built from the arguments.
func ParseAgentArgs(args []string, stderr io.Writer) (*AgentFile, error) {
	global := flag.NewFlagSet("l8tunnel-agent", flag.ContinueOnError)
	global.SetOutput(stderr)
	global.Usage = func() { fmt.Fprint(stderr, AgentUsage) }
	configPath := global.String("config", "", "")
	f := &AgentFile{}
	global.StringVar(&f.Relay, "relay", "", "")
	global.StringVar(&f.ServerName, "server-name", "", "")
	global.StringVar(&f.CA, "ca", "", "")
	global.StringVar(&f.Token, "token", "", "")
	global.StringVar(&f.Cert, "cert", "", "")
	global.StringVar(&f.Key, "key", "", "")
	global.StringVar(&f.StatusSocket, "status-socket", "", "")
	global.StringVar(&f.Transport, "transport", "", "")
	global.StringVar(&f.Proxy, "proxy", "", "")
	global.StringVar(&f.Log.Format, "log-format", "", "")
	global.StringVar(&f.Log.Level, "log-level", "", "")
	if err := global.Parse(args); err != nil {
		return nil, err
	}
	rest := global.Args()

	if *configPath != "" {
		var others []string
		global.Visit(func(fl *flag.Flag) {
			if fl.Name != "config" {
				others = append(others, "--"+fl.Name)
			}
		})
		if len(others) > 0 || len(rest) > 0 {
			return nil, fmt.Errorf("--config can't be combined with %s", strings.Join(append(others, rest...), " "))
		}
		return LoadAgentFile(*configPath)
	}

	if len(rest) == 0 {
		return nil, fmt.Errorf("a tunnel type (tcp or ssh) or --config is required\n\n%s", AgentUsage)
	}
	t, err := parseTunnelArgs(rest[0], rest[1:], stderr)
	if err != nil {
		return nil, err
	}
	f.Tunnels = []TunnelFile{t}
	return f, nil
}

func parseTunnelArgs(typ string, args []string, stderr io.Writer) (TunnelFile, error) {
	t := TunnelFile{Type: typ}
	if len(args) > 0 && !strings.HasPrefix(args[0], "-") {
		target, _, err := parseTarget(args[0])
		if err != nil {
			return t, err
		}
		if strings.Contains(args[0], "://") {
			target = args[0] // keep the scheme; AgentConfig applies it
		}
		t.Target = target
		args = args[1:]
	}
	fs := flag.NewFlagSet("l8tunnel-agent "+typ, flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() { fmt.Fprint(stderr, AgentUsage) }
	fs.StringVar(&t.Name, "name", "", "")
	fs.BoolVar(&t.InsecureSkipVerify, "insecure-skip-verify", false, "")
	fs.Var((*stringList)(&t.AllowIPs), "allow-ip", "")
	fs.Var((*stringList)(&t.DenyIPs), "deny-ip", "")
	var basic stringList
	fs.Var(&basic, "basic-auth", "")
	fs.StringVar(&t.AccessToken, "access-token", "", "")
	port := fs.Uint("port", 0, "")
	if err := fs.Parse(args); err != nil {
		return t, err
	}
	for _, b := range basic {
		user, hash, ok := strings.Cut(b, ":")
		if !ok {
			return t, fmt.Errorf("--basic-auth %q must be user:bcrypt-hash", b)
		}
		t.BasicAuth = append(t.BasicAuth, BasicAuthUser{User: user, PasswordHash: hash})
	}
	if fs.NArg() > 0 {
		return t, fmt.Errorf("unexpected arguments: %s", strings.Join(fs.Args(), " "))
	}
	if *port > 65535 {
		return t, fmt.Errorf("--port %d is not a valid port", *port)
	}
	t.PublicPort = uint32(*port)
	return t, nil
}

// stringList is a repeatable string flag.
type stringList []string

func (l *stringList) String() string { return strings.Join(*l, ",") }

func (l *stringList) Set(v string) error {
	*l = append(*l, v)
	return nil
}
