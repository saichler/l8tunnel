package tests

import (
	"fmt"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var forbidden = l8tunnel.ErrorCode_ERROR_CODE_FORBIDDEN

func TestTokenPolicyTypesAndNames(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 2, testPolicy: auth.Policy{Names: []string{"dev-*"}, Types: []string{"http"}}})
	target := startInspectServer(t)

	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "dev-ssh", Type: tcpType, Target: target})
	expectRemoteCode(t, err, forbidden)
	err = runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "prod", Type: httpType, Target: target})
	expectRemoteCode(t, err, forbidden)
	// A relay-assigned name must match the patterns too.
	err = runAgentExpectError(t, env, testToken, agent.TunnelConfig{Type: httpType, Target: target})
	expectRemoteCode(t, err, forbidden)

	startAgent(t, env, agent.TunnelConfig{Name: "dev-1", Type: httpType, Target: target})
	// Another token without a policy is unaffected.
	waitReady(t, runAgent(t, newAgent(t, env, otherToken, agent.TunnelConfig{Name: "prod", Type: tcpType, Target: target})))
}

func TestTokenPolicyMaxTunnels(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 5, testPolicy: auth.Policy{MaxTunnels: 2}})
	target := startEchoServer(t)

	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "a", Type: tcpType, Target: target},
		agent.TunnelConfig{Name: "b", Type: tcpType, Target: target},
		agent.TunnelConfig{Name: "c", Type: tcpType, Target: target})
	expectRemoteCode(t, err, forbidden)

	ra := startAgent(t, env,
		agent.TunnelConfig{Name: "a", Type: tcpType, Target: target},
		agent.TunnelConfig{Name: "b", Type: tcpType, Target: target})
	err = runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "c", Type: tcpType, Target: target})
	expectRemoteCode(t, err, forbidden)

	// Disconnected tunnels don't count, so the agent can come back.
	stopAgent(t, ra)
	startAgent(t, env,
		agent.TunnelConfig{Name: "a", Type: tcpType, Target: target},
		agent.TunnelConfig{Name: "b", Type: tcpType, Target: target})
}

func TestTokenPolicyPorts(t *testing.T) {
	portMin, portMax := freePortRange(t, 3)
	allowed := portMin + 1
	env := startRelayWith(t, relayOpts{portMin: portMin, portMax: portMax,
		testPolicy: auth.Policy{Ports: portRange(allowed, allowed)}})
	target := startEchoServer(t)

	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "fixed", Type: tcpType, Target: target, PublicPort: uint32(portMin)})
	expectRemoteCode(t, err, forbidden)

	ra := startAgent(t, env, agent.TunnelConfig{Name: "auto", Type: tcpType, Target: target})
	if got := ra.agent.Endpoints()[0].GetPublicPort(); got != uint32(allowed) {
		t.Fatalf("allocated port %d, want %d (the only port the policy allows)", got, allowed)
	}
}

func portRange(lo, hi int) string {
	return fmt.Sprintf("%d-%d", lo, hi)
}

func TestRevokedTokenDisconnectsAgentForGood(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "gone", Type: tcpType, Target: startEchoServer(t)})
	port := ra.agent.Endpoints()[0].GetPublicPort()

	rec, err := env.store.TokenByName("test")
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.DeleteToken(rec.ID); err != nil {
		t.Fatal(err)
	}
	if n := env.srv.DisconnectToken(rec.ID); n != 1 {
		t.Fatalf("disconnected %d sessions, want 1", n)
	}
	// The agent reconnects, is refused, and stops: a bad token is fatal.
	select {
	case err := <-ra.done:
		ra.done <- err
		expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_UNAUTHORIZED)
	case <-time.After(5 * time.Second):
		t.Fatal("agent kept running with a revoked token")
	}
	waitUntil(t, 5*time.Second, "public port to close", func() bool {
		_, err := roundTrip(publicAddr(port), []byte("x"))
		return err != nil
	})
	// The name is free for other tokens right away (no grace period).
	waitReady(t, runAgent(t, newAgent(t, env, otherToken, agent.TunnelConfig{Name: "gone", Type: tcpType, Target: startEchoServer(t)})))
}

func TestPermanentReservationSurvivesRestart(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 3, grace: 100 * time.Millisecond})
	rec, err := env.store.TokenByName("test")
	if err != nil {
		t.Fatal(err)
	}
	port := env.portMax
	if err := env.srv.Reserve("home", rec.ID, port); err != nil {
		t.Fatal(err)
	}
	if err := env.store.PutReservation(storeReservation("home", rec.ID, port)); err != nil {
		t.Fatal(err)
	}
	target := startEchoServer(t)

	// Other tokens can't take the name, even long after the grace period.
	time.Sleep(300 * time.Millisecond)
	err = runAgentExpectError(t, env, otherToken, agent.TunnelConfig{Name: "home", Type: tcpType, Target: target})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)

	// The owner gets the reserved port without asking for it.
	ra := startAgent(t, env, agent.TunnelConfig{Name: "home", Type: tcpType, Target: target})
	if got := ra.agent.Endpoints()[0].GetPublicPort(); got != uint32(port) {
		t.Fatalf("reserved tunnel got port %d, want %d", got, port)
	}
	stopAgent(t, ra)

	env = env.restart(t)
	time.Sleep(300 * time.Millisecond)
	err = runAgentExpectError(t, env, otherToken, agent.TunnelConfig{Name: "home", Type: tcpType, Target: target})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)
	st := env.srv.Status()
	if len(st.Parked) != 1 || st.Parked[0].Name != "home" || !st.Parked[0].Permanent || st.Parked[0].Port != port {
		t.Fatalf("after restart, parked = %+v", st.Parked)
	}
}
