package tests

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/client"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
	"github.com/saichler/l8tunnel/go/types/tun"
	"golang.org/x/crypto/ssh"
)

// TestKindRelayCluster runs real agents against the two relays in KIND.
func TestKindRelayCluster(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	key := forwardKey(t)
	for _, id := range []string{kindRelay0, kindRelay1} {
		waitUntil(t, 60*time.Second, id+" ready", func() bool {
			r := liveRelay(t, c, id)
			return r != nil && r.State == tun.TunRelayState_TUN_RELAY_STATE_READY && r.PodIp != ""
		})
	}
	tok := issueToken(t, c, uniqueName("k2"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	other := issueToken(t, c, uniqueName("k2o"), nil)
	t.Cleanup(func() { revokeToken(c, other.TokenId) })

	boxName, webName, agentID := uniqueName("box"), uniqueName("web"), uniqueName("agent")
	tunnels := []agent.TunnelConfig{
		{Name: boxName, Type: tcpType, Target: startEchoServer(t)},
		{Name: webName, Type: httpType, Target: startInspectServer(t)},
	}
	a := waitReady(t, kindAgent(t, ca, kindRelay0TLS, tok.Token, agentID, tunnels...))
	port := a.agent.Endpoints()[0].GetPublicPort()
	if port < 22000 || port > 22999 {
		t.Fatalf("allocated port %d outside the cluster range", port)
	}

	t.Run("live records", func(t *testing.T) {
		waitUntil(t, 20*time.Second, "live records", func() bool {
			box, ag := liveTunnel(t, c, boxName), liveAgent(t, c, agentID)
			return box != nil && box.RelayId == kindRelay0 && box.PublicPort == int32(port) &&
				ag != nil && ag.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE && ag.RelayId == kindRelay0 &&
				ag.Version == "test" && ag.Transport == tun.TunAgentTransport_TUN_AGENT_TRANSPORT_TLS
		})
	})

	t.Run("mode A through the owner's stream port", func(t *testing.T) {
		if !echoes(edgeStream(t, key, kindRelay0Strm, boxName, "203.0.113.5:40000"), "hello") {
			t.Fatal("no echo through relay-0's stream port")
		}
		// No second hop: relay-1 doesn't serve the tunnel.
		if echoes(edgeStream(t, key, kindRelay1Strm, boxName, "203.0.113.5:40000"), "hello") {
			t.Fatal("relay-1 served a stream for relay-0's tunnel")
		}
		// A header signed with another key is refused.
		if echoes(edgeStream(t, []byte("wrong-key-wrong-key-wrong-key-00"), kindRelay0Strm, boxName, "203.0.113.5:40000"), "hello") {
			t.Fatal("a stream with a bad signature got through")
		}
	})

	t.Run("mode B and HTTP forwarded by the other relay", func(t *testing.T) {
		var out bytes.Buffer
		err := client.Connect(t.Context(), client.Config{Host: boxName + "." + kindBase, RelayAddr: kindRelay1TLS,
			CAFile: ca.caFile, Proxy: "none"}, strings.NewReader("via relay-1"), &out)
		if err != nil || out.String() != "via relay-1" {
			t.Fatalf("mode B through relay-1: %q %v", out.String(), err)
		}
		seen := getSeen(t, relayHTTPSClient(t, ca, kindRelay1TLS), "https://"+webName+"."+kindBase+"/x", nil)
		if seen.URI != "/x" {
			t.Fatalf("HTTP through relay-1: %+v", seen)
		}
	})

	parent := t // agents that outlive a subtest are tied to the parent test
	t.Run("names are held across relays", func(t *testing.T) {
		stopAgent(t, a)
		waitUntil(t, 20*time.Second, "parked", func() bool {
			r := liveTunnel(t, c, boxName)
			return r != nil && r.State == tun.TunLiveState_TUN_LIVE_STATE_GRACE
		})
		err := runAgentKindExpectError(t, ca, kindRelay1TLS, other.Token, agent.TunnelConfig{Name: boxName, Type: tcpType, Target: startEchoServer(t)})
		var rerr *protocol.RemoteError
		if !errors.As(err, &rerr) || rerr.Code != l8tunnel.ErrorCode_ERROR_CODE_NAME_TAKEN {
			t.Fatalf("another token took a held name: %v", err)
		}
		// The same token reclaims it through relay-1, with the same port.
		a = waitReady(t, kindAgent(parent, ca, kindRelay1TLS, tok.Token, agentID, tunnels...))
		if got := a.agent.Endpoints()[0].GetPublicPort(); got != port {
			t.Fatalf("reclaimed port %d, want %d", got, port)
		}
		waitUntil(t, 20*time.Second, "moved to relay-1", func() bool {
			r := liveTunnel(t, c, boxName)
			return r != nil && r.RelayId == kindRelay1 && r.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE
		})
	})

	t.Run("SSH gateway reaches a tunnel on the other relay", func(t *testing.T) {
		// The tunnel is on relay-1 now; use relay-0's gateway.
		_, priv, _ := ed25519.GenerateKey(rand.Reader)
		signer, _ := ssh.NewSignerFromKey(priv)
		line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(signer.PublicKey())))
		c.mustDo(post, common.AreaAccess, common.GatewayKeyService, &tun.TunGatewayKey{Name: uniqueName("gw"), PublicKey: line, Tunnels: []string{boxName}}, nil)
		var conn *ssh.Client
		waitUntil(t, 30*time.Second, "gateway login", func() bool {
			var err error
			conn, err = ssh.Dial("tcp", "localhost:30222", &ssh.ClientConfig{User: "gw", Auth: []ssh.AuthMethod{ssh.PublicKeys(signer)},
				HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 5 * time.Second})
			return err == nil
		})
		defer conn.Close()
		ch, err := conn.Dial("tcp", boxName+":22")
		if err != nil {
			t.Fatal(err)
		}
		if !echoes(ch, "over ssh") {
			t.Fatal("no echo through the gateway")
		}
	})

	t.Run("operator disconnect, drain and resume", func(t *testing.T) {
		before := liveAgent(t, c, agentID).SessionId
		ctl(t, c, &tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DISCONNECT_AGENT, AgentId: agentID})
		waitUntil(t, 30*time.Second, "reconnected with a new session", func() bool {
			ag := liveAgent(t, c, agentID)
			return ag != nil && ag.SessionId != before && ag.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE
		})
		ctl(t, c, &tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_DRAIN, RelayId: kindRelay1})
		waitUntil(t, 30*time.Second, "drained", func() bool {
			ag, r := liveAgent(t, c, agentID), liveRelay(t, c, kindRelay1)
			return r.State == tun.TunRelayState_TUN_RELAY_STATE_DRAINING && ag.State == tun.TunAgentState_TUN_AGENT_STATE_GRACE &&
				ag.DisconnectReason == tun.TunDisconnectReason_TUN_DISCONNECT_REASON_RELAY_DRAINED
		})
		ctl(t, c, &tun.TunCtlCommand{Kind: tun.TunCtlCommandKind_TUN_CTL_COMMAND_KIND_RESUME, RelayId: kindRelay1})
		waitUntil(t, 30*time.Second, "back after resume", func() bool {
			r := liveTunnel(t, c, boxName)
			return r != nil && r.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE && r.PublicPort == int32(port)
		})
	})

	t.Run("revocation", func(t *testing.T) {
		if _, err := revokeToken(c, tok.TokenId); err != nil {
			t.Fatal(err)
		}
		select {
		case err := <-a.done:
			a.done <- err
		case <-time.After(30 * time.Second):
			t.Fatal("the agent kept running after its token was revoked")
		}
		waitUntil(t, 20*time.Second, "names released", func() bool {
			return liveTunnel(t, c, boxName) == nil && liveTunnel(t, c, webName) == nil
		})
	})
}

// runAgentKindExpectError runs an agent that must fail.
func runAgentKindExpectError(t *testing.T, ca *kindCA, relayAddr, token string, tunnels ...agent.TunnelConfig) error {
	t.Helper()
	ra := kindAgent(t, ca, relayAddr, token, uniqueName("x"), tunnels...)
	select {
	case err := <-ra.done:
		ra.done <- err
		return err
	case <-ra.agent.Ready():
		t.Fatal("agent registered, but it was expected to fail")
	case <-time.After(30 * time.Second):
		t.Fatal("agent neither failed nor registered within 30s")
	}
	return nil
}

// TestKindRegistryRestart: the registry's state is rebuilt from the relays.
func TestKindRegistryRestart(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("k2r"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	name := uniqueName("keep")
	waitReady(t, kindAgent(t, ca, kindRelay0TLS, tok.Token, uniqueName("ra"), agent.TunnelConfig{Name: name, Type: httpType, Target: startInspectServer(t)}))
	waitUntil(t, 20*time.Second, "live record", func() bool { return liveTunnel(t, c, name) != nil })

	kubectl(t, "delete", "pod", "l8tunnel-registry-0", "--wait=true")
	kubectl(t, "wait", "--for=condition=Ready", "pod/l8tunnel-registry-0", "--timeout=120s")
	waitUntil(t, 90*time.Second, "record re-announced", func() bool {
		r := liveTunnel(t, c, name)
		return r != nil && r.RelayId == kindRelay0 && r.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE
	})
	// And new claims work again.
	other := uniqueName("after")
	waitReady(t, kindAgent(t, ca, kindRelay1TLS, tok.Token, uniqueName("rb"), agent.TunnelConfig{Name: other, Type: httpType, Target: startInspectServer(t)}))
}
