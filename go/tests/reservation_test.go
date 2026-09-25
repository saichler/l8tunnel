package tests

import (
	"crypto/tls"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

func TestNameHeldForTokenDuringGracePeriod(t *testing.T) {
	grace := 500 * time.Millisecond
	env := startRelayWith(t, relayOpts{ports: 2, grace: grace})
	target := startEchoServer(t)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "keep", Type: tcpType, Target: target})
	port := ra.agent.Endpoints()[0].GetPublicPort()
	stopAgent(t, ra)

	// Another token can't take the parked name...
	err := runAgentExpectError(t, env, otherToken, agent.TunnelConfig{Name: "keep", Type: tcpType, Target: target})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)

	// ...but the same token gets the name back on the same port.
	ra2 := startAgent(t, env, agent.TunnelConfig{Name: "keep", Type: tcpType, Target: target})
	if got := ra2.agent.Endpoints()[0].GetPublicPort(); got != port {
		t.Fatalf("reclaimed tunnel got port %d, want %d", got, port)
	}
	stopAgent(t, ra2)

	// After the grace period the name is free for anyone.
	time.Sleep(3 * grace)
	waitReady(t, runAgent(t, newAgent(t, env, otherToken, agent.TunnelConfig{Name: "keep", Type: tcpType, Target: target})))
}

func TestReconnectedAgentTakesOverStaleSession(t *testing.T) {
	env := startRelay(t, 1)
	startAgentWithID := func(banner string) *runningAgent {
		return waitReady(t, runAgent(t, newAgentWithID(t, env, testToken, "same-agent",
			agent.TunnelConfig{Name: "box", Type: tcpType, Target: startBannerServer(t, banner)})))
	}
	stale := startAgentWithID("stale")
	port := stale.agent.Endpoints()[0].GetPublicPort()

	// The same agent ID connecting again means the old session is dead
	// even if the relay hasn't noticed yet: the new session takes over.
	fresh := startAgentWithID("fresh")
	if got := fresh.agent.Endpoints()[0].GetPublicPort(); got != port {
		t.Fatalf("takeover got port %d, want %d", got, port)
	}
	if got, err := readBanner(publicAddr(port)); err != nil || got != "fresh" {
		t.Fatalf("mode A reached %q (err %v), want the new session", got, err)
	}
	if got, err := connect(t, env, "box."+baseDomain, nil); err != nil || string(got) != "fresh" {
		t.Fatalf("mode B reached %q (err %v), want the new session", got, err)
	}
}

func TestDifferentAgentSameTokenCantTakeActiveName(t *testing.T) {
	env := startRelay(t, 2)
	startAgent(t, env, agent.TunnelConfig{Name: "mine", Type: tcpType, Target: startEchoServer(t)})
	err := runAgentExpectError(t, env, testToken, agent.TunnelConfig{Name: "mine", Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN)
}

// startSilentRelay accepts agents, completes the handshake with a short
// heartbeat interval, and then never answers a Ping. It counts sessions.
func startSilentRelay(t *testing.T, pki *testPKI) (string, *atomic.Int32) {
	t.Helper()
	cert, err := tls.LoadX509KeyPair(pki.certFile, pki.keyFile)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{protocol.ALPN},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	var sessions atomic.Int32
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			sessions.Add(1)
			go serveSilently(conn)
		}
	}()
	return ln.Addr().String(), &sessions
}

func serveSilently(conn net.Conn) {
	mux, err := transport.NewServerSession(conn, testLogger())
	if err != nil {
		return
	}
	defer mux.Close()
	control, err := mux.Accept()
	if err != nil {
		return
	}
	msg := &l8tunnel.ControlMessage{}
	if protocol.ReadMessage(control, msg) != nil {
		return
	}
	protocol.WriteMessage(control, &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Welcome{
		Welcome: &l8tunnel.Welcome{SessionId: "silent", HeartbeatIntervalMs: 50},
	}})
	if protocol.ReadMessage(control, msg) != nil {
		return
	}
	var endpoints []*l8tunnel.Endpoint
	for i, spec := range msg.GetRegister().GetTunnels() {
		endpoints = append(endpoints, &l8tunnel.Endpoint{TunnelId: protocol.RandomID(4), Name: spec.GetName(),
			Type: spec.GetType(), PublicPort: uint32(30000 + i)})
	}
	protocol.WriteMessage(control, &l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Registered{
		Registered: &l8tunnel.Registered{Endpoints: endpoints},
	}})
	// Swallow Pings without answering until the agent gives up.
	for protocol.ReadMessage(control, msg) == nil {
	}
}

func TestAgentReconnectsWhenRelayStopsAnswering(t *testing.T) {
	pki := newPKI(t)
	addr, sessions := startSilentRelay(t, pki)
	env := &relayEnv{pki: pki, addr: addr}
	startAgent(t, env, agent.TunnelConfig{Name: "x", Type: tcpType, Target: unusedAddr(t)})
	waitUntil(t, 5*time.Second, "agent to reconnect after missed heartbeats", func() bool {
		return sessions.Load() >= 2
	})
}
