// Command main is the l8tunnel management backend: the ORM services, the
// issuing service and the edge-node reports.
package main

import (
	"fmt"
	"os"

	"github.com/saichler/l8bus/go/overlay/vnic"
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8common/go/system"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/services"
	"github.com/saichler/l8tunnel/go/tunnel/config"
)

func main() {
	cluster, err := config.LoadClusterFile("")
	if err != nil {
		fmt.Fprintln(os.Stderr, "l8tunnel backend:", err)
		os.Exit(1)
	}
	common.SetCluster(cluster)

	resources := l8common.CreateResources("l8tunnel-"+os.Getenv("HOSTNAME"), false)
	common.RegisterTypes(resources)
	nic := vnic.NewVirtualNetworkInterface(resources, nil)
	nic.Start()
	nic.WaitForConnection()

	services.ActivateBackend(common.DB_CREDS, common.DB_NAME, nic)
	// Required system services (Events, Notify, IntegCfg) come from l8common.
	system.Activate(common.DB_CREDS, common.DB_NAME, nic)
	services.StartMaintenance(nic)
	resources.Logger().Info("l8tunnel backend services activated")
	l8common.WaitForSignal(resources)
}
