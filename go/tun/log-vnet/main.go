// Command log-vnet is the l8tunnel logs network: the log service that
// System > Logs reads, fed by a log-agent on every node.
package main

import (
	"github.com/saichler/l8bus/go/overlay/vnet"
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8logfusion/go/agent/logserver"
)

func main() {
	resources := l8common.CreateResources("l8tunnel-log-vnet", true)
	net := vnet.NewVNet(resources, true)
	net.Start()
	logserver.ActivateLogService("/data/logsdb/l8tunnel", net.VnetVnic())
	resources.Logger().Info("l8tunnel logs vnet started")
	l8common.WaitForSignal(resources)
}
