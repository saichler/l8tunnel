// Command l8tunnel is the client helper.
//
// "l8tunnel connect <host>" reaches a TCP/SSH tunnel through the relay's
// TLS port, for use as an OpenSSH ProxyCommand:
//
//	Host *.tunnel.example.com
//	    ProxyCommand l8tunnel connect %h
//
// "l8tunnel hash-password" prints a bcrypt hash for basic_auth.
package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/client"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

const usage = `usage:
  l8tunnel connect [--relay host:port] [--ca file] [--access-token T] [--proxy url] <name>.<base-domain>
  l8tunnel hash-password < password
  l8tunnel version

connect:
  --relay host:port   relay TLS address (default: <host>:443)
  --ca file           CA certificate to trust for the relay (default: system roots)
  --access-token T    token for tunnels that require one (default: $L8TUNNEL_ACCESS_TOKEN)
  --proxy url         http://proxy:port, "none", or default HTTPS_PROXY/NO_PROXY

hash-password reads one line from stdin and prints its bcrypt hash, e.g.
  read -rs PW && echo "$PW" | l8tunnel hash-password
`

func main() {
	err := run(os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("missing command")
	}
	switch args[0] {
	case "connect":
		return connect(args[1:])
	case "hash-password":
		return hashPassword()
	case "version", "--version", "-version":
		fmt.Println("l8tunnel", version)
		return nil
	}
	fmt.Fprint(os.Stderr, usage)
	return fmt.Errorf("unknown command %q", args[0])
}

func connect(args []string) error {
	fs := flag.NewFlagSet("l8tunnel connect", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var cfg client.Config
	fs.StringVar(&cfg.RelayAddr, "relay", "", "")
	fs.StringVar(&cfg.CAFile, "ca", "", "")
	fs.StringVar(&cfg.AccessToken, "access-token", os.Getenv("L8TUNNEL_ACCESS_TOKEN"), "")
	fs.StringVar(&cfg.Proxy, "proxy", "", "")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return fmt.Errorf("expected exactly one host name")
	}
	cfg.Host = fs.Arg(0)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	err := client.Connect(ctx, cfg, os.Stdin, os.Stdout)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func hashPassword() error {
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return fmt.Errorf("read password from stdin: %w", err)
	}
	hash, err := auth.HashPassword(strings.TrimRight(line, "\r\n"))
	if err != nil {
		return err
	}
	fmt.Println(hash)
	return nil
}
