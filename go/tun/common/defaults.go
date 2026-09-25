// Package common holds what every l8tunnel Layer 8 process shares: the API
// prefix, service names and areas, type registration, the service callback
// helper, and the conversions between the management model (go/types/tun)
// and the relay's own types.
package common

// PREFIX is the REST API prefix (login.json apiPrefix).
const PREFIX = "/tun/"

// Service areas: one per module (Maintainability).
const (
	AreaAccess = byte(40)
	AreaEdge   = byte(41)
	AreaLive   = byte(42)
	AreaAlerts = byte(43)
)

// Service names (at most 10 characters).
const (
	TokenService       = "TunToken"
	ReservationService = "TunResv"
	GatewayKeyService  = "TunGwKey"
	AgentCertService   = "TunAgCert"
	IssueService       = "TunIssue"
	DomainService      = "EdgeDomain"
	EdgeNodeService    = "EdgeNode"
	LiveService        = "TunLive"
	AgentService       = "TunAgent"
	RelayService       = "TunRelay"
	AlertService       = "TunAlert"
	// RelayCtlService is the listener every relay activates; owners push
	// the changes relays act on to it (plan §16.2).
	RelayCtlService = "TunRlyCtl"
	// EdgeCtlService is the listener every edge activates.
	EdgeCtlService = "EdgeCtl"
)

// FileStore (l8services) keeps uploaded certificates; it runs in the web
// process (plan §16.4).
const (
	FileStoreService = "FileStore"
	FileStoreArea    = byte(0)
	// CertDocumentID is the FileStore document ID for edge certificates;
	// their storage paths must start with CertStoragePrefix.
	CertDocumentID    = "edgecert"
	CertStoragePrefix = "/data/l8files/edgecert/"
)

// AllowSimulatedEnv set to "true" lets the owning process accept records
// marked simulated (mock data in run-local.sh and KIND only).
const AllowSimulatedEnv = "L8TUNNEL_ALLOW_SIMULATED"

// RequestTimeout is the vnic request timeout, in seconds.
const RequestTimeout = 15

// DB_CREDS and DB_NAME name the Postgres credentials in the security
// config: credentials[DB_CREDS].creds[DB_NAME].
var DB_CREDS = "postgres"
var DB_NAME = "l8tunnel"
