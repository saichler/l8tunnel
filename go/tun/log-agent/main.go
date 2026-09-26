// Command log-agent collects the l8tunnel log files on its node (every
// process writes them under the security config's log directory) and
// sends them to the log-vnet.
package main

import (
	"fmt"
	"os"

	"github.com/saichler/l8bus/go/overlay/vnic"
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8logfusion/go/agent/logs"
	"github.com/saichler/l8logfusion/go/types/l8logf"
	"github.com/saichler/l8utils/go/utils/ipsegment"
)

func main() {
	ip := os.Getenv("NODE_IP")
	if ip == "" {
		fmt.Println("NODE_IP is not set; using the machine IP")
		ip = ipsegment.MachineIP
	}
	path := os.Getenv("LOGPATH")
	if path == "" {
		path = "/data/logs/l8tunnel"
	}
	file := os.Getenv("LOGFILE")
	if file == "" {
		file = "*"
	}
	r := l8common.CreateResources("l8tunnel-log-agent", true)
	r.SysConfig().RemoteVnet = ip
	nic := vnic.NewVirtualNetworkInterface(r, nil)
	nic.Start()
	nic.WaitForConnection()
	logs.NewLogCollector(&l8logf.L8LogConfig{Path: path, Name: file}, nic).Collect()
}
