package tests

import (
	"net/http"
	"net/netip"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// An agent token isn't a management bearer, and a management bearer isn't
// an agent token.
func TestKindTokenSeparation(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("sep"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })

	asAgent := &kindClient{t: t, base: c.base, token: tok.Token, http: c.http}
	qerr := asAgent.query(common.AreaLive, common.RelayService, "select * from TunRelay", &tun.TunRelayList{})
	if qerr == nil {
		t.Fatal("an agent token was accepted as a management bearer")
	}
	t.Logf("agent token as a bearer: %v", qerr)
	err := runAgentKindExpectError(t, ca, kindRelay0TLS, c.token,
		agent.TunnelConfig{Name: uniqueName("sep"), Type: tcpType, Target: startEchoServer(t)})
	if err == nil {
		t.Fatal("a management bearer was accepted as an agent token")
	}
	t.Logf("management bearer at the relay: %v", err)
}

// When the relay pod holding an agent dies, the agent reconnects through
// the edge and its tunnel comes back with the same name and port.
func TestKindRelayPodLoss(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("loss"), &tun.TunTokenPolicy{Ports: "22000-22009"})
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	name, agentID := uniqueName("lbox"), uniqueName("lagent")
	a := waitReady(t, kindAgent(t, ca, kindEdgeHTTPS, tok.Token, agentID,
		agent.TunnelConfig{Name: name, Type: tcpType, Target: startEchoServer(t)}))
	port := a.agent.Endpoints()[0].GetPublicPort()

	var owner string
	waitUntil(t, 20*time.Second, "live record", func() bool {
		r := liveTunnel(t, c, name)
		if r == nil || r.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE {
			return false
		}
		owner = r.RelayId
		return true
	})
	t.Cleanup(func() {
		for _, id := range []string{kindRelay0, kindRelay1} {
			kubectl(t, "wait", "--for=condition=Ready", "pod/"+id, "--timeout=180s")
		}
	})
	session := liveAgent(t, c, agentID).SessionId
	kubectl(t, "delete", "pod", owner, "--wait=true")

	waitUntil(t, 180*time.Second, "tunnel back on a live relay", func() bool {
		ag := liveAgent(t, c, agentID)
		if ag == nil || ag.SessionId == session {
			return false
		}
		r := liveTunnel(t, c, name)
		if r == nil || r.State != tun.TunLiveState_TUN_LIVE_STATE_ACTIVE || r.PublicPort != int32(port) {
			return false
		}
		got, err := roundTrip(localAddr(int(port)), []byte("after loss"))
		return err == nil && string(got) == "after loss"
	})
	if ag := liveAgent(t, c, agentID); ag == nil || ag.State != tun.TunAgentState_TUN_AGENT_STATE_ONLINE {
		t.Fatalf("agent record after the relay loss: %+v", ag)
	}
	t.Logf("tunnel moved from %s to %s", owner, liveTunnel(t, c, name).RelayId)
}

// trafficProbe keeps requesting url until stopped, counting failures.
type trafficProbe struct {
	stop     chan struct{}
	done     chan struct{}
	ok, fail int
	lastErr  string
}

func startTrafficProbe(client *http.Client, url string) *trafficProbe {
	p := &trafficProbe{stop: make(chan struct{}), done: make(chan struct{})}
	go func() {
		defer close(p.done)
		for {
			select {
			case <-p.stop:
				return
			default:
			}
			resp, err := client.Get(url)
			if err == nil {
				resp.Body.Close()
				if resp.StatusCode != http.StatusOK {
					err = &probeError{resp.Status}
				}
			}
			if err != nil {
				p.fail++
				p.lastErr = err.Error()
			} else {
				p.ok++
			}
			time.Sleep(100 * time.Millisecond)
		}
	}()
	return p
}

func (p *trafficProbe) finish() (ok, fail int, lastErr string) {
	close(p.stop)
	<-p.done
	return p.ok, p.fail, p.lastErr
}

type probeError struct{ status string }

func (e *probeError) Error() string { return "status " + strings.TrimSpace(e.status) }

// The agent record matches the real agent (through the edge), its RTT and
// heartbeat update, and a clean stop parks every tunnel with the reason.
func TestKindAgentRecord(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("rec"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	box, web, agentID := uniqueName("rbox"), uniqueName("rweb"), uniqueName("ragent")
	a := waitReady(t, kindAgent(t, ca, kindEdgeHTTPS, tok.Token, agentID,
		agent.TunnelConfig{Name: box, Type: tcpType, Target: startEchoServer(t)},
		agent.TunnelConfig{Name: web, Type: httpType, Target: startInspectServer(t)}))

	var first *tun.TunAgent
	waitUntil(t, 30*time.Second, "agent record", func() bool {
		first = liveAgent(t, c, agentID)
		return first != nil && first.State == tun.TunAgentState_TUN_AGENT_STATE_ONLINE && first.TunnelCount == 2
	})
	if first.Version != "test" || first.Os != runtime.GOOS || first.Arch != runtime.GOARCH ||
		first.Transport != tun.TunAgentTransport_TUN_AGENT_TRANSPORT_TLS || first.TokenId != tok.TokenId {
		t.Fatalf("agent record %+v", first)
	}
	// The public IP is the client's, carried by the edge, not a pod's.
	ip, err := netip.ParseAddr(first.PublicIp)
	if err != nil || netip.MustParsePrefix("10.244.0.0/16").Contains(ip) {
		t.Fatalf("public IP %q", first.PublicIp)
	}
	waitUntil(t, 60*time.Second, "RTT and heartbeat updated", func() bool {
		ag := liveAgent(t, c, agentID)
		return ag != nil && ag.RttUs > 0 && ag.LastHeartbeat > first.LastHeartbeat
	})

	stopAgent(t, a)
	waitUntil(t, 30*time.Second, "every tunnel parked", func() bool {
		ag := liveAgent(t, c, agentID)
		b, w := liveTunnel(t, c, box), liveTunnel(t, c, web)
		return ag != nil && ag.State == tun.TunAgentState_TUN_AGENT_STATE_GRACE &&
			ag.DisconnectReason == tun.TunDisconnectReason_TUN_DISCONNECT_REASON_AGENT_CLOSED &&
			ag.GraceUntil > time.Now().Unix() &&
			b != nil && b.State == tun.TunLiveState_TUN_LIVE_STATE_GRACE && w != nil && w.State == tun.TunLiveState_TUN_LIVE_STATE_GRACE
	})
}

// Reading tokens through the UI (where a deny rule blanks secretHash) must
// not change what the relays read: the agent still connects afterwards.
func TestKindTokenSurvivesUIRead(t *testing.T) {
	c := newKindClient(t, "admin", "admin")
	ca := installTunnelCert(t, c)
	tok := issueToken(t, c, uniqueName("uiread"), nil)
	t.Cleanup(func() { revokeToken(c, tok.TokenId) })
	if err := c.query(common.AreaAccess, common.TokenService, "select * from TunToken", &tun.TunTokenList{}); err != nil {
		t.Fatal(err)
	}
	a := waitReady(t, kindAgent(t, ca, kindRelay0TLS, tok.Token, uniqueName("uiagent"),
		agent.TunnelConfig{Name: uniqueName("uibox"), Type: tcpType, Target: startEchoServer(t)}))
	stopAgent(t, a)
}
