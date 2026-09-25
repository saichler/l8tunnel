package reservations

import (
	"fmt"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"google.golang.org/protobuf/proto"
)

func newTunResvServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "TunReservation",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.TunReservation); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*tun.TunReservation).ReservationId)
		},
		Validate: validate,
		Changed:  common.PushToRelays,
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	r := e.(*tun.TunReservation)
	all, err := Reservations(vnic)
	if err != nil {
		return nil, err
	}
	check := r
	if action == ifs.PATCH {
		// Validate the reservation as it will be after the patch.
		check = merged(r, all)
		if check == nil {
			return nil, fmt.Errorf("reservation %s doesn't exist", r.ReservationId)
		}
	}
	if err := common.Cluster().Rules().CheckReservation(check.Name, int(check.PublicPort)); err != nil {
		return nil, err
	}
	tok, err := tokens.Token(check.TokenId, vnic)
	if err != nil {
		return nil, err
	}
	if tok == nil {
		return nil, fmt.Errorf("token %s doesn't exist", check.TokenId)
	}
	for _, o := range all {
		if o.ReservationId == check.ReservationId {
			continue
		}
		if o.Name == check.Name {
			return nil, fmt.Errorf("tunnel name %q is already reserved", check.Name)
		}
		if check.PublicPort != 0 && o.PublicPort == check.PublicPort {
			return nil, fmt.Errorf("port %d is already reserved for %q", check.PublicPort, o.Name)
		}
	}
	host := check.Name + "." + common.Cluster().BaseDomain
	if owner, err := domains.Owner(host, vnic); err != nil {
		return nil, err
	} else if owner != "" {
		return nil, fmt.Errorf("%s is an edge domain (%s); pick another tunnel name", host, owner)
	}
	if action == ifs.POST && r.CreatedAt == 0 {
		r.CreatedAt = time.Now().Unix()
	}
	return nil, nil
}

// merged is the stored reservation with the patch's set fields applied, or
// nil when it doesn't exist.
func merged(patch *tun.TunReservation, all []*tun.TunReservation) *tun.TunReservation {
	for _, o := range all {
		if o.ReservationId != patch.ReservationId {
			continue
		}
		m := proto.Clone(o).(*tun.TunReservation)
		if patch.Name != "" {
			m.Name = patch.Name
		}
		if patch.TokenId != "" {
			m.TokenId = patch.TokenId
		}
		if patch.PublicPort != 0 {
			m.PublicPort = patch.PublicPort
		}
		return m
	}
	return nil
}
