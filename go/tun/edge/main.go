// Command edge is the l8tunnel edge: the reverse proxy and load balancer
// the router forwards to, routing by domain to sites and relays.
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
	"github.com/saichler/l8tunnel/go/tun/edgenode"
	"github.com/saichler/l8tunnel/go/tunnel/config"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	cluster, err := config.LoadClusterFile("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel edge:", err)
		os.Exit(1)
	}
	common.SetCluster(cluster)
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	resources := l8common.CreateResources("l8tunnel-edge-"+os.Getenv("NODE_NAME"), false)
	common.RegisterTypes(resources)
	nic := vnic.NewVirtualNetworkInterface(resources, nil)
	nic.Start()
	nic.WaitForConnection()

	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))
	if err := edgenode.Run(ctx, nic, version, logger); err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel edge:", err)
		os.Exit(1)
	}
}
