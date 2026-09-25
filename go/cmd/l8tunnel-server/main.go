// Command l8tunnel-server is the public relay. With a command argument it
// manages a running relay through its admin socket instead.
package main

import (
	"context"
	"flag"
	"fmt"
	"net"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8tunnel/go/tunnel/store"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "/etc/l8tunnel/server.yaml", "server configuration file")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Usage = func() { fmt.Fprint(os.Stderr, admin.ServerUsage) }
	flag.Parse()

	var err error
	switch {
	case *showVersion:
		fmt.Println("l8tunnel-server", version)
	case flag.NArg() > 0:
		err = runCommand(*configPath, flag.Args())
	default:
		err = serve(*configPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-server:", err)
		os.Exit(1)
	}
}

func runCommand(configPath string, args []string) error {
	file, err := config.LoadServerFile(configPath)
	if err != nil {
		return err
	}
	return admin.RunServerCommand(file.AdminSocket(), args, os.Stdout, os.Stderr)
}

func serve(configPath string) error {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	file, err := config.LoadServerFile(configPath)
	if err != nil {
		return err
	}
	logger, err := file.Log.NewLogger(os.Stderr)
	if err != nil {
		return err
	}
	st, err := store.Open(file.DatabasePath())
	if err != nil {
		return err
	}
	defer st.Close()
	srv, err := file.NewRelay(ctx, logger, st, version)
	if err != nil {
		return err
	}
	adminLn, err := admin.ListenUnix(file.AdminSocket())
	if err != nil {
		return err
	}
	var metricsLn net.Listener
	if file.Metrics.Listen != "" {
		if metricsLn, err = net.Listen("tcp", file.Metrics.Listen); err != nil {
			adminLn.Close()
			return fmt.Errorf("metrics.listen: %w", err)
		}
	}
	if err := srv.Start(); err != nil {
		adminLn.Close()
		return err
	}
	go admin.Serve(ctx, adminLn, admin.RelayHandler(srv, st, logger), logger)
	logger.Info("admin socket listening", "path", file.AdminSocket())
	if metricsLn != nil {
		go admin.Serve(ctx, metricsLn, srv.MetricsHandler(), logger)
		logger.Info("metrics listening", "addr", metricsLn.Addr().String())
	}

	<-ctx.Done()
	logger.Info("shutting down")
	return srv.Close()
}
