package mocks

import (
	"crypto/tls"
	"fmt"
	"net/http"
	"os"
	"time"
)

// RunMockGenerator uploads the l8tunnel mock data to a running deployment
// (KIND), phase by phase.
func RunMockGenerator(address, user, password string, insecure bool) {
	fmt.Printf("l8tunnel mock data generator\n")
	fmt.Printf("Server: %s  User: %s\n\n", address, user)
	httpClient := &http.Client{Timeout: 30 * time.Second}
	if insecure {
		httpClient.Transport = &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}
	}
	client := NewClient(address, httpClient)
	if err := client.Authenticate(user, password); err != nil {
		fmt.Printf("Authentication failed: %v\n", err)
		os.Exit(1)
	}
	store := &MockDataStore{}
	if err := RunAllPhases(client, store); err != nil {
		fmt.Printf("\nMock data failed: %v\n", err)
		os.Exit(1)
	}
	PrintSummary(store)
}

// PrintSummary lists what each phase created.
func PrintSummary(s *MockDataStore) {
	fmt.Printf("\nCreated:\n")
	for _, row := range []struct {
		name string
		n    int
	}{
		{"tokens", len(s.TunTokenIDs)}, {"reservations", len(s.TunResvIDs)}, {"gateway keys", len(s.TunGwKeyIDs)},
		{"agent certificates", len(s.TunCertIDs)}, {"edge domains", len(s.TunDomainIDs)}, {"alert rules", len(s.TunAlertIDs)},
		{"edge nodes (simulated)", len(s.TunEdgeIDs)}, {"relays (simulated)", len(s.TunRelayIDs)},
		{"agents (simulated)", len(s.TunAgentIDs)}, {"tunnels (simulated)", len(s.TunTunnelIDs)}, {"users", len(s.TunUserIDs)},
	} {
		fmt.Printf("  %-24s %d\n", row.name, row.n)
	}
	for _, u := range s.TunUserIDs {
		fmt.Printf("  demo login: %s\n", u)
	}
}
