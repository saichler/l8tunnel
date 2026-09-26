package tests

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// OldAgentEnv names an l8tunnel-agent binary built before cluster mode
// (for example dist/l8tunnel-agent-*-5b19bbc-linux-amd64/bin/l8tunnel-agent).
const OldAgentEnv = "L8TUNNEL_OLD_AGENT"

// TestKindOldAgentBinary: an agent binary from before cluster mode
// connects through the edge unchanged (plan §8, wire compatibility), and
// its TCP (mode A) and HTTP tunnels carry traffic.
func TestKindOldAgentBinary(t *testing.T) {
	bin := os.Getenv(OldAgentEnv)
	if bin == "" {
		t.Skipf("set %s to an old l8tunnel-agent binary", OldAgentEnv)
	}
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("old"), &tun.TunTokenPolicy{Ports: "22000-22009"})
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })

	boxName, webName := uniqueName("oldbox"), uniqueName("oldweb")
	dir := t.TempDir()
	config := filepath.Join(dir, "agent.yaml")
	if err := os.WriteFile(config, []byte(fmt.Sprintf(`relay: %s
server_name: %s
ca: %s
token: %s
status_socket: %s
tunnels:
  - name: %s
    type: tcp
    target: %s
  - name: %s
    type: http
    target: %s
`, kindEdgeHTTPS, kindControl, ca.caFile, tok.Token, filepath.Join(dir, "status.sock"),
		boxName, startEchoServer(t), webName, startInspectServer(t))), 0o600); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	cmd := exec.Command(bin, "-config", config)
	cmd.Stdout, cmd.Stderr = &out, &out
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cmd.Process.Kill()
		cmd.Wait()
		if t.Failed() {
			t.Logf("old agent output:\n%s", out.String())
		}
	})

	var box *tun.TunLiveTunnel
	waitUntil(t, 30*time.Second, "the old agent's tunnels registered", func() bool {
		box = liveTunnelIfAny(c, boxName)
		return box != nil && liveTunnelIfAny(c, webName) != nil
	})
	got, err := roundTrip(localAddr(int(box.PublicPort)), []byte("old agent"))
	if err != nil || string(got) != "old agent" {
		t.Fatalf("mode A through the old agent (port %d): %q %v", box.PublicPort, got, err)
	}
	seen := getSeen(t, relayHTTPSClient(t, ca, kindEdgeHTTPS), "https://"+webName+"."+kindBase+"/old", nil)
	if seen.URI != "/old" {
		t.Fatalf("HTTP through the old agent: %+v", seen)
	}
	agents := &tun.TunAgentList{}
	if err := c.query(common.AreaLive, common.AgentService, "select * from TunAgent where tokenId="+tok.TokenId, agents); err != nil {
		t.Fatal(err)
	}
	if len(agents.List) != 1 || agents.List[0].State != tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
		t.Fatalf("the old agent's record: %+v", agents.List)
	}
	t.Logf("old agent %s (version %q, %s/%s) served mode A on port %d and HTTP", agents.List[0].AgentId,
		agents.List[0].Version, agents.List[0].Os, agents.List[0].Arch, box.PublicPort)
}

// liveTunnelIfAny returns the active live record of a tunnel, or nil.
func liveTunnelIfAny(c *kindClient, name string) *tun.TunLiveTunnel {
	list := &tun.TunLiveTunnelList{}
	if err := c.query(common.AreaLive, common.LiveService, "select * from TunLiveTunnel where name="+name, list); err != nil {
		return nil
	}
	for _, t := range list.List {
		if t.State == tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			return t
		}
	}
	return nil
}
