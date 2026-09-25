package gwkeys

import (
	"fmt"
	"strings"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"google.golang.org/protobuf/proto"
)

func newTunGwKeyServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "TunGatewayKey",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.TunGatewayKey); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*tun.TunGatewayKey).KeyId)
		},
		Validate: validate,
		Changed:  common.PushToRelays,
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	k := e.(*tun.TunGatewayKey)
	all, err := Keys(vnic)
	if err != nil {
		return nil, err
	}
	check := k
	if action == ifs.PATCH {
		if check = merged(k, all); check == nil {
			return nil, fmt.Errorf("gateway key %s doesn't exist", k.KeyId)
		}
	}
	// The same parsing and grant rules as the standalone relay's admin API;
	// it also normalizes the key and computes its fingerprint.
	parsed, err := auth.NewGatewayKey(check.Name, check.PublicKey, check.Tunnels)
	if err != nil {
		return nil, err
	}
	for _, o := range all {
		if o.KeyId == check.KeyId {
			continue
		}
		if strings.EqualFold(o.Name, check.Name) {
			return nil, fmt.Errorf("a gateway key named %q already exists", o.Name)
		}
		if o.Fingerprint == parsed.Fingerprint {
			return nil, fmt.Errorf("this public key is already registered as %q", o.Name)
		}
	}
	if action != ifs.PATCH || k.PublicKey != "" {
		k.PublicKey = parsed.PublicKey
	}
	k.Fingerprint = parsed.Fingerprint
	if action == ifs.POST && k.CreatedAt == 0 {
		k.CreatedAt = time.Now().Unix()
	}
	return nil, nil
}

func merged(patch *tun.TunGatewayKey, all []*tun.TunGatewayKey) *tun.TunGatewayKey {
	for _, o := range all {
		if o.KeyId != patch.KeyId {
			continue
		}
		m := proto.Clone(o).(*tun.TunGatewayKey)
		if patch.Name != "" {
			m.Name = patch.Name
		}
		if patch.PublicKey != "" {
			m.PublicKey = patch.PublicKey
		}
		if len(patch.Tunnels) > 0 {
			m.Tunnels = patch.Tunnels
		}
		return m
	}
	return nil
}
