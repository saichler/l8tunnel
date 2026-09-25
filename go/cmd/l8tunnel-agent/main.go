// Command l8tunnel-agent exposes local services through an l8tunnel relay.
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
	"github.com/saichler/l8tunnel/go/tunnel/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	err := run(logger, os.Args[1:])
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-agent:", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, args []string) error {
	file, err := config.ParseAgentArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	cfg, err := file.AgentConfig(logger, version)
	if err != nil {
		return err
	}
	a, err := agent.New(cfg)
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
