// Package services activates each process's services. The backend is the
// only process that activates the ORM services (SingleOwnerDatabaseTable).
package services

import (
	"time"

	"github.com/saichler/l8tunnel/go/tun/access/agentcerts"
	"github.com/saichler/l8tunnel/go/tun/access/gwkeys"
	"github.com/saichler/l8tunnel/go/tun/access/issue"
	"github.com/saichler/l8tunnel/go/tun/access/reservations"
	"github.com/saichler/l8tunnel/go/tun/access/tokens"
	"github.com/saichler/l8tunnel/go/tun/alerts"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/tun/edge/nodes"
	"github.com/saichler/l8types/go/ifs"
)

// maintenanceInterval is how often the backend re-checks the built-in
// TUNNEL_BASE domain.
const maintenanceInterval = time.Minute

// ActivateBackend activates the backend's services.
func ActivateBackend(creds, dbname string, vnic ifs.IVNic) {
	tokens.Activate(creds, dbname, vnic)
	reservations.Activate(creds, dbname, vnic)
	gwkeys.Activate(creds, dbname, vnic)
	agentcerts.Activate(creds, dbname, vnic)
	domains.Activate(creds, dbname, vnic)
	alerts.Activate(creds, dbname, vnic)
	nodes.Activate(vnic)
	issue.Activate(vnic)
}

// StartMaintenance keeps the TUNNEL_BASE domain present and in line with
// cluster.yaml: now, and every minute (a plain ORM DELETE can't be refused).
// It also starts the alert evaluator.
func StartMaintenance(vnic ifs.IVNic) {
	alerts.StartEvaluator(vnic)
	go func() {
		for {
			if err := domains.EnsureTunnelBase(vnic); err != nil {
				vnic.Resources().Logger().Warning("tunnel base domain: ", err.Error())
			}
			time.Sleep(maintenanceInterval)
		}
	}()
}
