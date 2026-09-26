package mocks

import (
	"fmt"
	"time"
)

// RunAllPhases runs the phases in dependency order (plan §7.4). The data
// is meant for a fresh deployment (run-local.sh, a new KIND cluster);
// names get a run tag and ports a run offset, so running it again against
// the same deployment usually works too (1 in 9 runs repeats an offset).
func RunAllPhases(c *Client, s *MockDataStore) error {
	now := time.Now().Unix()
	tag := fmt.Sprintf("-%x", now%0xffff)
	s.portOffset = int32(now % 9)
	phases := []struct {
		name string
		run  func() error
	}{
		{"1: tokens (TunIssue)", func() error { return generateTokens(c, s, tag) }},
		{"2: reservations", func() error { return generateReservations(c, s, tag) }},
		{"2: gateway keys", func() error { return generateGatewayKeys(c, s, tag) }},
		{"3: agent certificates (TunIssue)", func() error { return generateCertificates(c, s) }},
		{"4: edge domains (FileStore certificates)", func() error { return generateEdgeDomains(c, s, tag) }},
		{"5: alert rules", func() error { return generateAlerts(c, s, tag) }},
		{"6: edge node (simulated)", func() error { return generateEdgeNode(c, s, tag) }},
		{"7-8: relays, agents and tunnels (simulated)", func() error { return generateLive(c, s, tag) }},
		{"9: demo users (Security API)", func() error { return generateUsers(c, s, tag) }},
	}
	for _, p := range phases {
		fmt.Printf("Phase %s... ", p.name)
		if err := p.run(); err != nil {
			fmt.Println("failed")
			return fmt.Errorf("phase %s: %w", p.name, err)
		}
		fmt.Println("done")
	}
	return nil
}
