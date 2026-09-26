package mocks

// MockDataStore holds the IDs each phase creates, for the phases that
// reference them.
type MockDataStore struct {
	TunTokenIDs   []string
	TunTokenNames []string
	TunResvIDs    []string
	TunGwKeyIDs   []string
	TunCertIDs    []string
	TunDomainIDs  []string
	TunAlertIDs   []string
	TunRelayIDs   []string
	TunAgentIDs   []string
	TunTunnelIDs  []string
	TunEdgeIDs    []string
	TunUserIDs    []string

	portOffset int32 // this run's shift of the ports that must be unique
}
