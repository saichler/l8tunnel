package tests

import (
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
)

// fakeAddrs is the machine's address list as the agent sees it, so a test
// can take the agent's network away (a Wi-Fi switch) and bring it back.
type fakeAddrs struct {
	v atomic.Pointer[[]net.Addr]
}

func newFakeAddrs(cidrs ...string) *fakeAddrs {
	f := &fakeAddrs{}
	f.set(cidrs...)
	return f
}

func (f *fakeAddrs) set(cidrs ...string) {
	var addrs []net.Addr
	for _, c := range cidrs {
		ip, n, err := net.ParseCIDR(c)
		if err != nil {
			panic(err)
		}
		addrs = append(addrs, &net.IPNet{IP: ip, Mask: n.Mask})
	}
	f.v.Store(&addrs)
}

func (f *fakeAddrs) lookup() ([]net.Addr, error) {
	return *f.v.Load(), nil
}

// When the address its relay connection uses goes away, the agent drops
// the session at once instead of waiting for missed heartbeats (the
// connection itself looks alive here), and reconnects once it's back.
func TestAgentDropsSessionWhenItsAddressGoes(t *testing.T) {
	env := startRelay(t, 1)
	addrs := newFakeAddrs("127.0.0.1/8", "192.0.2.10/24")
	ra := waitReady(t, runAgent(t, newAgentWith(t, env, func(c *agent.Config) {
		c.Tunnels = []agent.TunnelConfig{{Type: tcpType, Target: startEchoServer(t)}}
		c.NetworkCheckInterval = 100 * time.Millisecond
		c.LocalAddrs = addrs.lookup
	})))

	addrs.set("192.0.2.10/24") // the network the session used is gone
	waitUntil(t, 2*time.Second, "the session dropped", func() bool { return !ra.agent.Status().Connected })

	addrs.set("127.0.0.1/8", "192.0.2.10/24") // a network is back
	waitUntil(t, 3*time.Second, "reconnected", func() bool {
		st := ra.agent.Status()
		return st.Connected && st.Reconnects >= 1
	})
}

// While the agent waits to retry, a change in the machine's addresses (a
// new network) makes it retry at once instead of finishing the wait.
func TestAgentRetriesAtOnceWhenTheNetworkChanges(t *testing.T) {
	env := startRelay(t, 1)
	addrs := newFakeAddrs("127.0.0.1/8")
	ra := waitReady(t, runAgent(t, newAgentWith(t, env, func(c *agent.Config) {
		c.Tunnels = []agent.TunnelConfig{{Type: tcpType, Target: startEchoServer(t)}}
		c.ReconnectMin, c.ReconnectMax = time.Minute, time.Minute
		c.NetworkCheckInterval = 100 * time.Millisecond
		c.LocalAddrs = addrs.lookup
	})))

	// The relay goes away and comes back: the agent now waits a minute.
	env.restart(t)
	waitUntil(t, 5*time.Second, "the session ended", func() bool { return !ra.agent.Status().Connected })
	time.Sleep(300 * time.Millisecond)
	if ra.agent.Status().Connected {
		t.Fatal("reconnected before the network changed; the test needs a long wait")
	}

	addrs.set("127.0.0.1/8", "198.51.100.7/24") // joined a new network
	waitUntil(t, 3*time.Second, "reconnected after the network change", func() bool { return ra.agent.Status().Connected })
}
