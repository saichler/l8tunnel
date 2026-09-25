// Package reservations is the TunResv service: tunnel names (and optional
// tcp/ssh public ports) permanently reserved for a token.
package reservations

import (
	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
)

const (
	ServiceName = common.ReservationService
	ServiceArea = common.AreaAccess
)

// Activate activates the ORM-backed service; only the backend calls it.
func Activate(creds, dbname string, vnic ifs.IVNic) {
	sla := l8common.NewOrmSLA(ServiceName, ServiceArea, "ReservationId", newTunResvServiceCallback(),
		&tun.TunReservation{}, &tun.TunReservationList{})
	l8common.ActivateService(sla, creds, dbname, vnic)
}

// Reservations returns every reservation.
func Reservations(vnic ifs.IVNic) ([]*tun.TunReservation, error) {
	elems, err := l8common.GetEntities(ServiceName, ServiceArea, &tun.TunReservation{}, vnic)
	if err != nil {
		return nil, err
	}
	out := make([]*tun.TunReservation, 0, len(elems))
	for _, e := range elems {
		if r, ok := e.(*tun.TunReservation); ok && r.ReservationId != "" {
			out = append(out, r)
		}
	}
	return out, nil
}
