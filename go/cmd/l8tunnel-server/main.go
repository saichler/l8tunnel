// Command l8tunnel-server is the public relay.
package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/config"
)

func main() {
	configPath := flag.String("config", "/etc/l8tunnel/server.yaml", "server configuration file")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(logger, *configPath); err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-server:", err)
		os.Exit(1)
	}
}

func run(logger *slog.Logger, configPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	file, err := config.LoadServerFile(configPath)
	if err != nil {
		return err
	}
	srv, err := file.NewRelay(ctx, logger)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}
	<-ctx.Done()
	logger.Info("shutting down")
	return srv.Close()
}
