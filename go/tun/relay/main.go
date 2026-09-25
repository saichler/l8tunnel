// Command relay is an l8tunnel relay in cluster mode: agent sessions and
// tunnel traffic, with names and ports claimed through the registry.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/saichler/l8bus/go/overlay/vnic"
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/relaynode"
	"github.com/saichler/l8tunnel/go/tunnel/config"
	"github.com/saichler/l8types/go/ifs"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cluster, err := config.LoadClusterFile("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel relay:", err)
		os.Exit(1)
	}
	common.SetCluster(cluster)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resources := l8common.CreateResources("l8tunnel-relay-"+os.Getenv("POD_NAME"), false)
	common.RegisterTypes(resources)
	ifs.SetNetworkMode(ifs.NETWORK_K8s)
	nic := vnic.NewVirtualNetworkInterface(resources, nil)
	nic.Start()
	nic.WaitForConnection()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := relaynode.Run(ctx, nic, version, logger); err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel relay:", err)
		os.Exit(1)
	}
}
