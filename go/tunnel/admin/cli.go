package admin

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

// ServerUsage describes the relay's admin commands.
const ServerUsage = `usage: l8tunnel-server [--config server.yaml] <command>

commands:
  status [--json]                        connected agents, tunnels and parked names
  token create --name N [policy flags]   create an agent token (printed once)
      --names p1,p2    allowed tunnel names (patterns like dev-*)
      --types t1,t2    allowed tunnel types (tcp, ssh, http, tls)
      --max-tunnels N  maximum connected tunnels
      --ports A-B      allowed tcp/ssh public ports
      --require-cert   agents must present a client certificate
      --domains p1,p2  custom domains the token may serve (patterns like *.example.com)
  token list                             list tokens (never their secrets)
  token revoke NAME                      delete a token and disconnect its agents
  agent-cert issue --token T --out PREFIX [--days 365]
                                         write PREFIX.crt and PREFIX.key for an agent
  gateway-key add --name N (--key "ssh-ed25519 ..." | --key-file F) --tunnels 'p1,p2'
                                         allow a public key through the SSH gateway
  gateway-key list
  gateway-key remove NAME
  reservation add --name N --token T [--port P]
                                         bind a tunnel name (and port) to a token
  reservation list
  reservation remove NAME

Run as root or the relay's user: the admin socket is mode 0600.
`

// RunServerCommand runs a relay admin command against the socket.
func RunServerCommand(socket string, args []string, stdout, stderr io.Writer) error {
	c := NewClient(socket)
	if len(args) == 0 {
		fmt.Fprint(stderr, ServerUsage)
		return fmt.Errorf("missing command")
	}
	switch strings.Join(args[:min(2, len(args))], " ") {
	case "token create":
		return tokenCreate(c, args[2:], stdout, stderr)
	case "token list":
		return tokenList(c, stdout)
	case "token revoke":
		if len(args) != 3 {
			return fmt.Errorf("usage: token revoke NAME")
		}
		resp, err := c.RevokeToken(args[2])
		if err == nil {
			fmt.Fprintf(stdout, "revoked token %q; disconnected %d agent session(s)\n", args[2], resp.Disconnected)
		}
		return err
	case "gateway-key add":
		return gatewayKeyAdd(c, args[2:], stdout, stderr)
	case "gateway-key list":
		return gatewayKeyList(c, stdout)
	case "gateway-key remove":
		if len(args) != 3 {
			return fmt.Errorf("usage: gateway-key remove NAME")
		}
		if err := c.RemoveGatewayKey(args[2]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed gateway key %q\n", args[2])
		return nil
	case "agent-cert issue":
		return certIssue(c, args[2:], stdout, stderr)
	case "reservation add":
		return reservationAdd(c, args[2:], stdout, stderr)
	case "reservation list":
		return reservationList(c, stdout)
	case "reservation remove":
		if len(args) != 3 {
			return fmt.Errorf("usage: reservation remove NAME")
		}
		if err := c.Unreserve(args[2]); err != nil {
			return err
		}
		fmt.Fprintf(stdout, "removed reservation %q\n", args[2])
		return nil
	}
	if args[0] == "status" {
		return relayStatus(c, args[1:], stdout, stderr)
	}
	fmt.Fprint(stderr, ServerUsage)
	return fmt.Errorf("unknown command %q", strings.Join(args, " "))
}

func splitList(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func tokenCreate(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("token create", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "token name")
	names := fs.String("names", "", "allowed tunnel names, comma separated")
	types := fs.String("types", "", "allowed tunnel types, comma separated")
	maxTunnels := fs.Int("max-tunnels", 0, "maximum connected tunnels")
	ports := fs.String("ports", "", "allowed tcp/ssh public ports, A-B")
	requireCert := fs.Bool("require-cert", false, "agents must present a client certificate")
	domains := fs.String("domains", "", "allowed custom domains, comma separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: token create --name N [--names ...] [--types ...] [--max-tunnels N] [--ports A-B]")
	}
	resp, err := c.CreateToken(CreateTokenRequest{Name: *name, Policy: auth.Policy{
		Names: splitList(*names), Types: splitList(*types), MaxTunnels: *maxTunnels, Ports: *ports,
		RequireCert: *requireCert, Domains: splitList(*domains),
	}})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "created token %q (id %s). It is shown only once:\n\n  %s\n\n", resp.Name, resp.ID, resp.Token)
	return nil
}

func policyString(p auth.Policy) string {
	var parts []string
	if len(p.Names) > 0 {
		parts = append(parts, "names="+strings.Join(p.Names, ","))
	}
	if len(p.Types) > 0 {
		parts = append(parts, "types="+strings.Join(p.Types, ","))
	}
	if p.MaxTunnels > 0 {
		parts = append(parts, fmt.Sprintf("max-tunnels=%d", p.MaxTunnels))
	}
	if p.Ports != "" {
		parts = append(parts, "ports="+p.Ports)
	}
	if p.RequireCert {
		parts = append(parts, "require-cert")
	}
	if len(p.Domains) > 0 {
		parts = append(parts, "domains="+strings.Join(p.Domains, ","))
	}
	if len(parts) == 0 {
		return "any"
	}
	return strings.Join(parts, " ")
}

func tokenList(c *Client, stdout io.Writer) error {
	tokens, err := c.Tokens()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tID\tCREATED\tCERTS\tPOLICY")
	for _, t := range tokens {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%d\t%s\n", t.Name, t.ID, t.Created.Format(time.RFC3339), t.Certs, policyString(t.Policy))
	}
	return tw.Flush()
}

func reservationAdd(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("reservation add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "tunnel name")
	token := fs.String("token", "", "token name")
	port := fs.Int("port", 0, "tcp/ssh public port")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *name == "" || *token == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: reservation add --name N --token T [--port P]")
	}
	res, err := c.Reserve(ReservationRequest{Name: *name, Token: *token, Port: *port})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "reserved %q for token %q", res.Name, res.Token)
	if res.Port != 0 {
		fmt.Fprintf(stdout, " on port %d", res.Port)
	}
	fmt.Fprintln(stdout)
	return nil
}

func reservationList(c *Client, stdout io.Writer) error {
	list, err := c.Reservations()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tTOKEN\tPORT\tCREATED")
	for _, r := range list {
		port := "-"
		if r.Port != 0 {
			port = fmt.Sprint(r.Port)
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", r.Name, r.Token, port, r.Created.Format(time.RFC3339))
	}
	return tw.Flush()
}

func relayStatus(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("status", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	st, err := c.RelayStatus()
	if err != nil {
		return err
	}
	if *asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintf(tw, "AGENTS (%d)\n", len(st.Sessions))
	fmt.Fprintln(tw, "TOKEN\tAGENT\tREMOTE\tVERSION\tUPTIME")
	for _, s := range st.Sessions {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s %s/%s\t%s\n", s.Token, s.AgentID, s.Remote, s.Version, s.OS, s.Arch,
			time.Since(s.ConnectedAt).Round(time.Second))
	}
	fmt.Fprintln(tw, "\nTUNNELS")
	fmt.Fprintln(tw, "NAME\tTYPE\tTOKEN\tPUBLIC\tCONNS (ACTIVE/TOTAL)\tIN\tOUT")
	for _, s := range st.Sessions {
		for _, t := range s.Tunnels {
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n", t.Name, t.Type, s.Token, t.PublicAddress,
				t.ActiveConns, t.TotalConns, bytesString(t.BytesIn), bytesString(t.BytesOut))
		}
	}
	if len(st.Parked) > 0 {
		fmt.Fprintln(tw, "\nPARKED (no agent connected)")
		fmt.Fprintln(tw, "NAME\tTYPE\tPORT\tHELD UNTIL")
		for _, p := range st.Parked {
			until := "reserved"
			if !p.Permanent {
				until = p.Expires.Format(time.RFC3339)
			}
			port := "-"
			if p.Port != 0 {
				port = fmt.Sprint(p.Port)
			}
			typ := p.Type
			if typ == "" {
				typ = "-"
			}
			fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", p.Name, typ, port, until)
		}
	}
	return tw.Flush()
}

// RunAgentStatus prints an agent's status from its status socket.
func RunAgentStatus(socket string, asJSON bool, stdout io.Writer) error {
	st, err := NewClient(socket).AgentStatus()
	if err != nil {
		return err
	}
	if asJSON {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(st)
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	state := "disconnected"
	if st.Connected {
		state = "connected for " + time.Since(st.ConnectedSince).Round(time.Second).String()
	}
	fmt.Fprintf(tw, "agent %s -> %s: %s (reconnects: %d)\n", st.AgentID, st.Relay, state, st.Reconnects)
	if st.LastError != "" {
		fmt.Fprintf(tw, "last error: %s\n", st.LastError)
	}
	fmt.Fprintln(tw, "\nNAME\tTYPE\tTARGET\tPUBLIC\tCONNS (ACTIVE/TOTAL)\tIN\tOUT")
	for _, t := range st.Tunnels {
		public := t.PublicAddress
		if public == "" {
			public = "-"
		}
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%d/%d\t%s\t%s\n", t.Name, t.Type, t.Target, public,
			t.ActiveConns, t.TotalConns, bytesString(t.BytesIn), bytesString(t.BytesOut))
	}
	return tw.Flush()
}

func bytesString(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

func certIssue(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("agent-cert issue", flag.ContinueOnError)
	fs.SetOutput(stderr)
	token := fs.String("token", "", "token name")
	out := fs.String("out", "", "output prefix: writes PREFIX.crt and PREFIX.key")
	days := fs.Int("days", 365, "validity in days")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *token == "" || *out == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: agent-cert issue --token T --out PREFIX [--days 365]")
	}
	resp, err := c.IssueCert(*token, *days)
	if err != nil {
		return err
	}
	certFile, keyFile := *out+".crt", *out+".key"
	if err := writeNewFile(keyFile, []byte(resp.Key), 0o600); err != nil {
		return err
	}
	if err := writeNewFile(certFile, []byte(resp.Cert), 0o644); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "issued certificate %s for token %q, valid until %s\n  %s\n  %s (keep private)\n",
		resp.Serial, *token, resp.Expires.Format(time.RFC3339), certFile, keyFile)
	return nil
}

// writeNewFile refuses to overwrite, so a key can't be silently replaced.
func writeNewFile(path string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

func gatewayKeyAdd(c *Client, args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("gateway-key add", flag.ContinueOnError)
	fs.SetOutput(stderr)
	name := fs.String("name", "", "key name")
	key := fs.String("key", "", "public key (authorized_keys format)")
	keyFile := fs.String("key-file", "", "file with the public key")
	tunnels := fs.String("tunnels", "", "tunnel names or patterns, comma separated")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if *keyFile != "" {
		data, err := os.ReadFile(*keyFile)
		if err != nil {
			return err
		}
		*key = string(data)
	}
	if *name == "" || *key == "" || *tunnels == "" || fs.NArg() > 0 {
		return fmt.Errorf("usage: gateway-key add --name N (--key K | --key-file F) --tunnels 'p1,p2'")
	}
	k, err := c.AddGatewayKey(GatewayKeyRequest{Name: *name, PublicKey: *key, Tunnels: splitList(*tunnels)})
	if err != nil {
		return err
	}
	fmt.Fprintf(stdout, "added gateway key %q (%s) for tunnels %s\n", k.Name, k.Fingerprint, strings.Join(k.Tunnels, ","))
	return nil
}

func gatewayKeyList(c *Client, stdout io.Writer) error {
	keys, err := c.GatewayKeys()
	if err != nil {
		return err
	}
	tw := tabwriter.NewWriter(stdout, 0, 4, 2, ' ', 0)
	fmt.Fprintln(tw, "NAME\tFINGERPRINT\tTUNNELS\tCREATED")
	for _, k := range keys {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", k.Name, k.Fingerprint, strings.Join(k.Tunnels, ","), k.Created.Format(time.RFC3339))
	}
	return tw.Flush()
}
