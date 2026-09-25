package tests

import (
	"bytes"
	"context"
	"crypto/rand"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/client"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var sshType = l8tunnel.TunnelType_TUNNEL_TYPE_SSH

func connect(t *testing.T, env *relayEnv, host string, payload []byte) ([]byte, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var out bytes.Buffer
	err := client.Connect(ctx, client.Config{Host: host, RelayAddr: env.addr, CAFile: env.pki.caFile},
		bytes.NewReader(payload), &out)
	return out.Bytes(), err
}

func TestModeBConnectRoundTrip(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "box", Type: sshType, Target: startEchoServer(t)})

	payload := make([]byte, 2<<20)
	rand.Read(payload)
	got, err := connect(t, env, "box."+baseDomain, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d", len(payload), len(got))
	}
}

func TestModeBHostNameIsCaseInsensitive(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "box", Type: tcpType, Target: startEchoServer(t)})
	got, err := connect(t, env, "BOX.Tunnel.Test.", []byte("hi"))
	if err != nil || string(got) != "hi" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestModeBRejectsUnknownHosts(t *testing.T) {
	env := startRelay(t, 1)
	startAgent(t, env, agent.TunnelConfig{Name: "box", Type: tcpType, Target: startEchoServer(t)})

	for _, host := range []string{
		"nobox." + baseDomain, // no such tunnel
		controlSNI,            // control SNI without the agent ALPN
	} {
		if _, err := connect(t, env, host, []byte("x")); err == nil {
			t.Errorf("%s: connect succeeded, want an error", host)
		}
	}
}

func TestModeBStopsWhenAgentLeaves(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "gone", Type: tcpType, Target: startEchoServer(t)})
	if _, err := connect(t, env, "gone."+baseDomain, []byte("x")); err != nil {
		t.Fatal(err)
	}
	stopAgent(t, ra)
	waitUntil(t, 5*time.Second, "mode B to be refused", func() bool {
		_, err := connect(t, env, "gone."+baseDomain, []byte("x"))
		return err != nil
	})
}

func TestTunnelNameReservedForControlSNI(t *testing.T) {
	env := startRelay(t, 1)
	err := runAgentExpectError(t, env, testToken,
		agent.TunnelConfig{Name: "connect", Type: tcpType, Target: unusedAddr(t)})
	expectRemoteCode(t, err, l8tunnel.ErrorCode_ERROR_CODE_INVALID_REQUEST)
}
