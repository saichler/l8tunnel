// Command registry is the single owner of the live tables: the claims
// engine that keeps tunnel names, ports and domains unique across relays.
package main

import (
	"fmt"
	"os"

	"github.com/saichler/l8bus/go/overlay/vnic"
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/live"
	"github.com/saichler/l8tunnel/go/tunnel/config"
)

func main() {
	cluster, err := config.LoadClusterFile("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel registry:", err)
		os.Exit(1)
	}
	common.SetCluster(cluster)

	resources := l8common.CreateResources("l8tunnel-registry-"+os.Getenv("HOSTNAME"), false)
	common.RegisterTypes(resources)
	nic := vnic.NewVirtualNetworkInterface(resources, nil)
	nic.Start()
	nic.WaitForConnection()

	live.Start(nic)
	resources.Logger().Info("l8tunnel registry started")
	l8common.WaitForSignal(resources)
}
