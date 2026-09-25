// Command main is the l8tunnel web server: the REST API (under /tun/) and
// the l8ui management UI. It also hosts FileStore, which keeps uploaded
// certificates, so exactly one instance runs (plan §16.4).
package main

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
)

func main() {
	svr := l8common.CreateWebServer("l8tunnel-web", common.RegisterTypes)
	svr.Start()
}
