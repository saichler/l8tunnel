// Command l8tunnel-agent exposes local services through an l8tunnel relay.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	var err error
	switch {
	case len(os.Args) > 1 && os.Args[1] == "status":
		err = status(os.Args[2:])
	case len(os.Args) > 1 && (os.Args[1] == "version" || os.Args[1] == "--version" || os.Args[1] == "-version"):
		fmt.Println("l8tunnel-agent", version)
	default:
		err = run(os.Args[1:])
	}
	if errors.Is(err, flag.ErrHelp) {
		return
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel-agent:", err)
		os.Exit(1)
	}
}

func status(args []string) error {
	fs := flag.NewFlagSet("l8tunnel-agent status", flag.ContinueOnError)
	socket := fs.String("socket", admin.DefaultAgentSocket, "the agent's status socket")
	asJSON := fs.Bool("json", false, "print JSON")
	if err := fs.Parse(args); err != nil {
		return err
	}
	return admin.RunAgentStatus(*socket, *asJSON, os.Stdout)
}

func run(args []string) error {
	file, err := config.ParseAgentArgs(args, os.Stderr)
	if err != nil {
		return err
	}
	logger, err := file.Log.NewLogger(os.Stderr)
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
	if file.StatusSocket != "" {
		ln, err := admin.ListenUnix(file.StatusSocket)
		if err != nil {
			return err
		}
		go admin.Serve(ctx, ln, admin.AgentHandler(a), logger)
	}
	if err := a.Run(ctx); err != nil && !errors.Is(err, context.Canceled) {
		return err
	}
	return nil
}
