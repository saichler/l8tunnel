// Command l8tunnel-server is the public relay.
package main

import (
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
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
	file, err := config.LoadServerFile(configPath)
	if err != nil {
		return err
	}
	cfg, err := file.RelayConfig(logger)
	if err != nil {
		return err
	}
	srv, err := relay.New(cfg)
	if err != nil {
		return err
	}
	if err := srv.Start(); err != nil {
		return err
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	logger.Info("shutting down", "signal", (<-sig).String())
	return srv.Close()
}
