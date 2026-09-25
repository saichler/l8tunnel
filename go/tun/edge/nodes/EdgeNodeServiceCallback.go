package nodes

import (
	"errors"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

func newEdgeNodeServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "EdgeNode",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.EdgeNode); return ok },
		// An edge reports under its own ID (its node name); nothing to
		// generate.
		SetID: func(interface{}) {},
		Validate: func(e interface{}, action ifs.Action, _ ifs.IVNic) (interface{}, error) {
			n := e.(*tun.EdgeNode)
			if action == ifs.POST || action == ifs.PUT {
				if n.EdgeId == "" {
					return nil, errors.New("edgeId is required")
				}
				if n.Simulated && !common.AllowSimulated() {
					return nil, errors.New("simulated records aren't accepted here")
				}
				if n.LastSeen == 0 {
					n.LastSeen = time.Now().Unix()
				}
			}
			return nil, nil
		},
	})
}
