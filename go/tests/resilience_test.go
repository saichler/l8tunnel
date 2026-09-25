package tests

import (
	"net"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

func TestAgentReconnectsAfterRelayRestart(t *testing.T) {
	env := startRelay(t, 2)
	ra := startAgent(t, env, agent.TunnelConfig{Type: tcpType, Target: startEchoServer(t)})
	first := ra.agent.Endpoints()[0]

	env = env.restart(t)
	var ep *l8tunnel.Endpoint
	waitUntil(t, 10*time.Second, "agent to re-register", func() bool {
		ep = ra.agent.Endpoints()[0]
		return ep.GetTunnelId() != first.GetTunnelId()
	})
	// The relay-assigned name is requested again, and the first free port
	// in the range is the same one.
	if ep.GetName() != first.GetName() || ep.GetPublicPort() != first.GetPublicPort() {
		t.Fatalf("after restart got %s:%d, want %s:%d",
			ep.GetName(), ep.GetPublicPort(), first.GetName(), first.GetPublicPort())
	}
	got, err := roundTrip(publicAddr(ep.GetPublicPort()), []byte("back"))
	if err != nil || string(got) != "back" {
		t.Fatalf("round trip after restart: got %q, err %v", got, err)
	}
}

func TestHeartbeatsKeepIdleSessionAlive(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, heartbeat: 50 * time.Millisecond})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "idle", Type: tcpType, Target: startEchoServer(t)})
	before := ra.agent.Endpoints()[0].GetTunnelId()

	time.Sleep(time.Second) // 20 heartbeat intervals
	if after := ra.agent.Endpoints()[0].GetTunnelId(); after != before {
		t.Fatal("the agent reconnected while idle")
	}
	got, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), []byte("still here"))
	if err != nil || string(got) != "still here" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

// rawSession is a hand-driven agent session that never sends heartbeats.
func rawSession(t *testing.T, env *relayEnv) (*transport.Session, *transport.Stream, *l8tunnel.Welcome) {
	t.Helper()
	tlsCfg, err := transport.ClientTLSConfig(controlSNI, env.pki.caFile)
	if err != nil {
		t.Fatal(err)
	}
	conn, err := transport.DialRelay(t.Context(), env.addr, tlsCfg)
	if err != nil {
		t.Fatal(err)
	}
	mux, err := transport.NewClientSession(conn, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	control, err := mux.Open()
	if err != nil {
		t.Fatal(err)
	}
	send := func(msg *l8tunnel.ControlMessage) *l8tunnel.ControlMessage {
		if err := protocol.WriteMessage(control, msg); err != nil {
			t.Fatal(err)
		}
		reply := &l8tunnel.ControlMessage{}
		if err := protocol.ReadMessage(control, reply); err != nil {
			t.Fatal(err)
		}
		return reply
	}
	welcome := send(&l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Hello{Hello: &l8tunnel.Hello{
		ProtocolVersion: protocol.Version, Token: testToken, AgentId: "raw",
	}}}).GetWelcome()
	if welcome == nil {
		t.Fatal("no Welcome")
	}
	reg := send(&l8tunnel.ControlMessage{Body: &l8tunnel.ControlMessage_Register{Register: &l8tunnel.Register{
		Tunnels: []*l8tunnel.TunnelSpec{{Name: "raw", Type: tcpType}},
	}}}).GetRegistered()
	if reg == nil {
		t.Fatal("no Registered")
	}
	return mux, control, welcome
}

func TestRelayDropsAgentThatMissesHeartbeats(t *testing.T) {
	env := startRelayWith(t, relayOpts{ports: 1, heartbeat: 100 * time.Millisecond})
	_, control, welcome := rawSession(t, env)
	if welcome.GetHeartbeatIntervalMs() != 100 {
		t.Fatalf("Welcome heartbeat = %dms, want 100", welcome.GetHeartbeatIntervalMs())
	}

	start := time.Now()
	control.SetReadDeadline(time.Now().Add(5 * time.Second))
	err := protocol.ReadMessage(control, &l8tunnel.ControlMessage{})
	if err == nil {
		t.Fatal("relay sent a message instead of dropping the silent session")
	}
	if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
		t.Fatal("relay did not drop the silent session within 5s")
	}
	if elapsed := time.Since(start); elapsed < 250*time.Millisecond {
		t.Fatalf("session dropped after %s, before 3 missed heartbeats", elapsed)
	}
}
