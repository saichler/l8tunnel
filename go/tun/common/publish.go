package common

import (
	"github.com/saichler/l8types/go/ifs"
)

// PushToRelays sends a change to every relay's TunRlyCtl listener; it fits
// Hooks.Changed. It is fire-and-forget: a relay that misses it catches up
// at its next re-read.
func PushToRelays(elem interface{}, action ifs.Action, vnic ifs.IVNic) {
	push(vnic, RelayCtlService, AreaLive, action, elem)
}

// PushToEdges sends a change to every edge's EdgeCtl listener.
func PushToEdges(elem interface{}, action ifs.Action, vnic ifs.IVNic) {
	push(vnic, EdgeCtlService, AreaEdge, action, elem)
}

func push(vnic ifs.IVNic, service string, area byte, action ifs.Action, elem interface{}) {
	if err := vnic.Multicast(service, area, action, elem); err != nil {
		vnic.Resources().Logger().Warning("push to ", service, " failed: ", err.Error())
	}
}
