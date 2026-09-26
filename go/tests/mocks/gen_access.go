package mocks

import (
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"strings"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"golang.org/x/crypto/ssh"
)

// Phase 1: tokens, through TunIssue (the only way to create one), with
// varied policies.
func generateTokens(c *Client, s *MockDataStore, tag string) error {
	types := []tun.TunTunnelType{tun.TunTunnelType_TUN_TUNNEL_TYPE_TCP, tun.TunTunnelType_TUN_TUNNEL_TYPE_SSH,
		tun.TunTunnelType_TUN_TUNNEL_TYPE_HTTP, tun.TunTunnelType_TUN_TUNNEL_TYPE_TLS}
	for i, name := range tokenNames {
		policy := &tun.TunTokenPolicy{}
		switch i % 5 {
		case 0: // anything
		case 1:
			policy.Names = []string{name + "-*"}
			policy.Types = []tun.TunTunnelType{types[1], types[2]}
		case 2:
			policy.MaxTunnels = int32(2 + i%3)
			policy.Ports = fmt.Sprintf("%d-%d", 22100+i*10, 22109+i*10)
		case 3:
			policy.Types = []tun.TunTunnelType{types[2], types[3]}
			policy.Domains = []string{"*." + name + ".example.test"}
		case 4:
			policy.RequireCert = true
			policy.Names = []string{name, name + "-web"}
		}
		resp := &tun.TunIssueResponse{}
		if err := post(c, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{
			Kind: tun.TunIssueKind_TUN_ISSUE_KIND_TOKEN, TokenName: name + tag,
			TokenDescription: tokenDescriptions[i%len(tokenDescriptions)], Policy: policy,
		}, resp); err != nil {
			return err
		}
		s.TunTokenIDs = append(s.TunTokenIDs, resp.TokenId)
		s.TunTokenNames = append(s.TunTokenNames, name+tag)
	}
	return nil
}

// Phase 2: reservations on the tokens, and gateway keys with grants.
func generateReservations(c *Client, s *MockDataStore, tag string) error {
	if len(s.TunTokenIDs) == 0 {
		return fmt.Errorf("reservations need the tokens of phase 1")
	}
	for i := 0; i < 8; i++ {
		r := &tun.TunReservation{
			Name:    fmt.Sprintf("%s-%s%s", tunnelPrefixes[i%len(tunnelPrefixes)], tokenNames[i], tag),
			TokenId: s.TunTokenIDs[i],
			Note:    "Reserved for " + tokenNames[i],
		}
		if i%2 == 0 {
			r.PublicPort = 22900 + s.portOffset*10 + int32(i) // mode A port held across restarts
		}
		if err := post(c, common.AreaAccess, common.ReservationService, r, nil); err != nil {
			return err
		}
		s.TunResvIDs = append(s.TunResvIDs, r.Name)
	}
	return nil
}

func generateGatewayKeys(c *Client, s *MockDataStore, tag string) error {
	for i := 0; i < 6; i++ {
		pub, _, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		sshPub, err := ssh.NewPublicKey(pub)
		if err != nil {
			return err
		}
		k := &tun.TunGatewayKey{
			Name:      fmt.Sprintf("gw-%s%s", []string{"sharon", "backup", "ci", "family", "support", "audit"}[i], tag),
			PublicKey: strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sshPub))),
			Tunnels:   []string{tunnelPrefixes[i%len(tunnelPrefixes)] + "-*", tokenNames[i] + "*"},
		}
		if err := post(c, common.AreaAccess, common.GatewayKeyService, k, nil); err != nil {
			return err
		}
		s.TunGwKeyIDs = append(s.TunGwKeyIDs, k.Name)
	}
	return nil
}

// Phase 3: agent certificates for a subset of the tokens (the ones whose
// policy requires one, and a few more).
func generateCertificates(c *Client, s *MockDataStore) error {
	if len(s.TunTokenIDs) == 0 {
		return fmt.Errorf("certificates need the tokens of phase 1")
	}
	for i := 4; i < len(s.TunTokenIDs); i += 3 {
		resp := &tun.TunIssueResponse{}
		if err := post(c, common.AreaAccess, common.IssueService, &tun.TunIssueRequest{
			Kind: tun.TunIssueKind_TUN_ISSUE_KIND_AGENT_CERT, TokenId: s.TunTokenIDs[i], CertDays: int32(90 + i*10),
		}, resp); err != nil {
			return err
		}
		s.TunCertIDs = append(s.TunCertIDs, resp.CertId)
	}
	return nil
}
