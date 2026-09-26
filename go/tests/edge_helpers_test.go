package tests

import (
	"io"
	"net"
	"os"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/edge"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// staticLive is the edge's view of relays and tunnels in tests.
type staticLive struct {
	mu     sync.Mutex
	relays []edge.RelayTarget
	hosts  map[string]edge.RelayTarget
}

func (l *staticLive) Relays() []edge.RelayTarget {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]edge.RelayTarget(nil), l.relays...)
}

func (l *staticLive) OwnerOfHost(host string) (edge.RelayTarget, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	r, ok := l.hosts[host]
	return r, ok
}

func (l *staticLive) OwnerOfPort(int) (edge.RelayTarget, string, bool) {
	return edge.RelayTarget{}, "", false
}

func newTestEdge(t *testing.T, live edge.Live) (*edge.Edge, *certs.Set) {
	t.Helper()
	set := certs.NewSet()
	e, err := edge.New(edge.Config{BaseDomain: baseDomain, ControlSNI: controlSNI, NodeIP: "127.0.0.1", BindHost: "127.0.0.1",
		ForwardKey: []byte("0123456789abcdef0123456789abcdef"), Live: live, Certs: set,
		ConnectionsPerSecond: 10000, ConnectionsBurst: 10000, Logger: testLogger()})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(e.Close)
	return e, set
}

// freePort returns a free 127.0.0.1 port.
func freePort(t *testing.T) int {
	t.Helper()
	p, _ := freePortRange(t, 1)
	return p
}

// startNamedServer answers every connection with its name.
func startNamedServer(t *testing.T, name string) (addr string, stop func()) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(name))
			c.Close()
		}
	}()
	return ln.Addr().String(), func() { ln.Close() }
}

// restartOn listens again on addr (after stop).
func restartOn(t *testing.T, addr, name string) func() {
	t.Helper()
	var ln net.Listener
	var err error
	for i := 0; i < 50; i++ {
		if ln, err = net.Listen("tcp", addr); err == nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			c.Write([]byte(name))
			c.Close()
		}
	}()
	return func() { ln.Close() }
}

// whoAnswers connects to addr and reads the backend's name ("" on failure).
func whoAnswers(addr string) string {
	c, err := net.DialTimeout("tcp", addr, 2*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	b, _ := io.ReadAll(c)
	return string(b)
}

func tcpSite(id, domain string, port int, lb tun.EdgeLbAlgorithm, targets ...string) *tun.EdgeDomain {
	return &tun.EdgeDomain{DomainId: id, Domain: domain, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE, Enabled: true,
		PortForwards: []*tun.EdgePortForward{{ForwardId: "f", ListenPort: int32(port), Protocol: tun.EdgeProtocol_EDGE_PROTOCOL_TCP,
			Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
			Targets: targets, Lb: lb, Enabled: true}}}
}

func localAddr(port int) string { return "127.0.0.1:" + strconv.Itoa(port) }

func readFile(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
