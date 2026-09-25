// Command l8tunnel is the client helper. "l8tunnel connect <host>" reaches
// a TCP/SSH tunnel through the relay's TLS port, for use as an OpenSSH
// ProxyCommand:
//
//	Host *.tunnel.example.com
//	    ProxyCommand l8tunnel connect %h
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/client"
)

const usage = `usage:
  l8tunnel connect [--relay host:port] [--ca file] <name>.<base-domain>

  --relay host:port   relay TLS address (default: <host>:443)
  --ca file           CA certificate to trust for the relay (default: system roots)
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
	if len(args) == 0 || args[0] != "connect" {
		fmt.Fprint(os.Stderr, usage)
		return fmt.Errorf("unknown or missing command")
	}
	fs := flag.NewFlagSet("l8tunnel connect", flag.ContinueOnError)
	fs.Usage = func() { fmt.Fprint(os.Stderr, usage) }
	var cfg client.Config
	fs.StringVar(&cfg.RelayAddr, "relay", "", "")
	fs.StringVar(&cfg.CAFile, "ca", "", "")
	if err := fs.Parse(args[1:]); err != nil {
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
