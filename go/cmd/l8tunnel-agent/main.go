// Command l8tunnel-agent exposes a local service through an l8tunnel relay.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	relayAddr := flag.String("relay", "", "relay control address, host:port")
	serverName := flag.String("server-name", "", "TLS server name of the relay (default: host of -relay)")
	caFile := flag.String("ca", "", "CA certificate to trust for the relay (default: system roots)")
	token := flag.String("token", "", "agent token (default: $L8TUNNEL_TOKEN)")
	name := flag.String("name", "", "tunnel name (default: assigned by the relay)")
	tunnelType := flag.String("type", "tcp", "tunnel type: tcp or ssh")
	target := flag.String("target", "", "local host:port to expose (ssh default: 127.0.0.1:22)")
	publicPort := flag.Uint("public-port", 0, "fixed public port on the relay (default: allocated)")
	flag.Parse()

	if *token == "" {
		*token = os.Getenv("L8TUNNEL_TOKEN")
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger, *relayAddr, *serverName, *caFile, *token, *name, *tunnelType, *target, uint32(*publicPort)); err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-agent:", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, relayAddr, serverName, caFile, token, name, tunnelType, target string, publicPort uint32) error {
	if serverName == "" {
		host, err := agent.ServerName(relayAddr)
		if err != nil {
			return err
		}
		serverName = host
	}
	tlsCfg, err := transport.ClientTLSConfig(serverName, caFile)
	if err != nil {
		return err
	}
	typ, err := agent.ParseTunnelType(tunnelType)
	if err != nil {
		return err
	}
	a, err := agent.New(agent.Config{
		RelayAddr: relayAddr,
		TLS:       tlsCfg,
		Token:     token,
		Version:   version,
		Tunnels:   []agent.TunnelConfig{{Name: name, Type: typ, Target: target, PublicPort: publicPort}},
		Logger:    logger,
	})
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
