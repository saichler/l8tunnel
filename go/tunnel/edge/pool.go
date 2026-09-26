package edge

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"math/rand/v2"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/edgeconf"
	"github.com/saichler/l8tunnel/go/types/tun"
)

const (
	dialTimeout        = 5 * time.Second
	dnsRefresh         = 30 * time.Second
	unhealthyAfter     = 3 // failed checks
	healthyAfter       = 2 // passed checks
	defaultHealthEvery = 10 * time.Second
)

// ErrNoHealthyMember: every member is down, disabled or refused the dial.
var ErrNoHealthyMember = errors.New("no healthy backend")

// member is one backend of a pool.
type member struct {
	addr     string
	host     string
	weight   int
	disabled bool
	healthy  atomic.Bool
	active   atomic.Int64

	mu        sync.Mutex
	fails     int
	passes    int
	lastErr   string
	lastCheck time.Time
	current   int // smooth weighted round robin
}

// pool is one port forward's backends and its load balancing.
type pool struct {
	id     string
	fwd    *tun.EdgePortForward
	nodeIP string
	log    *slog.Logger

	mu      sync.Mutex
	members []*member
	done    chan struct{}
}

func newPool(id string, fwd *tun.EdgePortForward, nodeIP string, log *slog.Logger) *pool {
	p := &pool{id: id, fwd: fwd, nodeIP: nodeIP, log: log, done: make(chan struct{})}
	if fwd.TargetKind == tun.EdgeTargetKind_EDGE_TARGET_KIND_RELAYS {
		return p // relays come from the live tables, not from a pool
	}
	p.members = p.resolveMembers(nil)
	go p.loop()
	return p
}

// resolveMembers builds the member list, keeping the state of members that
// are still there.
func (p *pool) resolveMembers(old []*member) []*member {
	keep := map[string]*member{}
	for _, m := range old {
		keep[m.addr] = m
	}
	add := func(host string, port, weight int, disabled bool, out []*member) []*member {
		addr := net.JoinHostPort(host, strconv.Itoa(port))
		m := keep[addr]
		if m == nil {
			m = &member{addr: addr, host: host}
			m.healthy.Store(true)
		}
		m.weight, m.disabled = weight, disabled
		return append(out, m)
	}
	var out []*member
	switch p.fwd.TargetKind {
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS:
		targets, _ := edgeconf.ParseTargets(p.fwd.Targets) // validated when stored
		for _, t := range targets {
			out = add(t.Host, t.Port, t.Weight, t.Disabled, out)
		}
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_DNS:
		ips, err := net.LookupHost(p.fwd.TargetDns)
		if err != nil {
			p.log.Warn("edge: DNS target", "name", p.fwd.TargetDns, "error", err)
			return old
		}
		for _, ip := range ips {
			out = add(ip, int(p.fwd.TargetPort), 1, false, out)
		}
	case tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL:
		out = add(p.nodeIP, int(p.fwd.TargetPort), 1, false, out)
	}
	return out
}

func (p *pool) stop() {
	select {
	case <-p.done:
	default:
		close(p.done)
	}
}

func (p *pool) snapshot() []*member {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]*member(nil), p.members...)
}

// pick chooses a healthy, enabled member not in tried.
func (p *pool) pick(client netip.Addr, tried map[*member]bool) *member {
	var cands []*member
	for _, m := range p.snapshot() {
		if !m.disabled && m.healthy.Load() && !tried[m] {
			cands = append(cands, m)
		}
	}
	if len(cands) == 0 {
		return nil
	}
	switch p.fwd.Lb {
	case tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_LEAST_CONN:
		best := cands[0]
		for _, m := range cands[1:] {
			// fewest active connections per unit of weight
			if m.active.Load()*int64(best.weight) < best.active.Load()*int64(m.weight) {
				best = m
			}
		}
		return best
	case tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_SOURCE_HASH:
		// Rendezvous hashing: a client keeps its member, and adding a
		// member moves only the clients it now wins.
		var best *member
		var bestScore uint64
		for _, m := range cands {
			h := fnv.New64a()
			h.Write(client.AsSlice())
			h.Write([]byte(m.addr))
			score := h.Sum64() / uint64(1<<20) * uint64(m.weight)
			if best == nil || score > bestScore {
				best, bestScore = m, score
			}
		}
		return best
	case tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_RANDOM:
		// Power of two choices.
		a, b := cands[rand.IntN(len(cands))], cands[rand.IntN(len(cands))]
		if b.active.Load() < a.active.Load() {
			return b
		}
		return a
	}
	return p.smoothRoundRobin(cands)
}

// smoothRoundRobin is nginx's smooth weighted round robin: members with
// weight 2 get two of every three picks, spread out.
func (p *pool) smoothRoundRobin(cands []*member) *member {
	p.mu.Lock()
	defer p.mu.Unlock()
	total := 0
	var best *member
	for _, m := range cands {
		m.current += m.weight
		total += m.weight
		if best == nil || m.current > best.current {
			best = m
		}
	}
	best.current -= total
	return best
}

// dial connects to a member, trying the next one when a dial fails (no
// client bytes have been sent yet, so this is always safe). The returned
// connection decrements the member's active count when closed.
func (p *pool) dial(ctx context.Context, client netip.Addr) (net.Conn, *member, error) {
	return p.dialFrom(ctx, client, nil)
}

// dialAddr connects to the member at addr (a TERMINATE request's pick),
// falling back to the other members when that dial fails.
func (p *pool) dialAddr(ctx context.Context, addr string) (net.Conn, *member, error) {
	for _, m := range p.snapshot() {
		if m.addr == addr {
			return p.dialFrom(ctx, netip.Addr{}, m)
		}
	}
	return p.dialFrom(ctx, netip.Addr{}, nil)
}

func (p *pool) dialFrom(ctx context.Context, client netip.Addr, first *member) (net.Conn, *member, error) {
	tried := map[*member]bool{}
	for {
		m := first
		if m == nil {
			m = p.pick(client, tried)
		}
		first = nil
		if m == nil {
			return nil, nil, ErrNoHealthyMember
		}
		tried[m] = true
		d := net.Dialer{Timeout: dialTimeout}
		conn, err := d.DialContext(ctx, "tcp", m.addr)
		if err != nil {
			m.failed(err.Error())
			p.log.Debug("edge: backend dial failed", "pool", p.id, "backend", m.addr, "error", err)
			continue
		}
		m.active.Add(1)
		return &countedConn{Conn: conn, m: m}, m, nil
	}
}

// failed records a failed check or dial; enough of them mark it down.
func (m *member) failed(why string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.fails++
	m.passes = 0
	m.lastErr = why
	m.lastCheck = time.Now()
	if m.fails >= unhealthyAfter {
		m.healthy.Store(false)
	}
}

func (m *member) passed() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.passes++
	m.lastCheck = time.Now()
	if m.passes >= healthyAfter || m.healthy.Load() {
		m.fails, m.lastErr = 0, ""
		m.healthy.Store(true)
	}
}

// countedConn keeps a member's active-connection count.
type countedConn struct {
	net.Conn
	m    *member
	once sync.Once
}

func (c *countedConn) Close() error {
	c.once.Do(func() { c.m.active.Add(-1) })
	return c.Conn.Close()
}

// CloseWrite half-closes a TCP backend connection.
func (c *countedConn) CloseWrite() error {
	if hc, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return hc.CloseWrite()
	}
	return errors.ErrUnsupported
}
