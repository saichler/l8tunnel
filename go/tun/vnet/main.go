// Command vnet is the l8tunnel virtual network switch every other l8tunnel
// process's vnic connects through.
package main

import (
	"os"

	"github.com/saichler/l8bus/go/overlay/vnet"
	l8common "github.com/saichler/l8common/go/common"
)

func main() {
	resources := l8common.CreateResources("l8tunnel-vnet-"+os.Getenv("HOSTNAME"), false)
	net := vnet.NewVNet(resources)
	net.Start()
	resources.Logger().Info("l8tunnel vnet started")
	l8common.WaitForSignal(resources)
}
