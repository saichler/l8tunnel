package agent

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"strings"
	"time"
)

// DefaultNetworkCheckInterval is how often the agent looks for a network
// change (a laptop switching Wi-Fi): often enough to reconnect within
// seconds, rare enough to cost nothing.
const DefaultNetworkCheckInterval = 5 * time.Second

// errNetworkChanged ends a session whose local address is gone.
var errNetworkChanged = errors.New("network changed")

// localIP is the local address of the relay connection, or nil when the
// connection has none (it isn't TCP).
func localIP(conn net.Conn) net.IP {
	if tcp, ok := conn.LocalAddr().(*net.TCPAddr); ok {
		return tcp.IP
	}
	return nil
}

// addrSet is this machine's addresses as a comparable string; ok is false
// when they can't be listed.
func (a *Agent) addrSet() (set string, ok bool) {
	addrs, err := a.cfg.LocalAddrs()
	if err != nil {
		a.log.Debug("listing local addresses failed", "error", err)
		return "", false
	}
	ips := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		if n, isNet := addr.(*net.IPNet); isNet {
			ips = append(ips, n.IP.String())
		} else {
			ips = append(ips, addr.String())
		}
	}
	sort.Strings(ips)
	return strings.Join(ips, ","), true
}

// watchAddress ends the session when ip is no longer one of this machine's
// addresses: the network it used is gone, and waiting for missed
// heartbeats would keep the machine unreachable for up to a minute.
func (a *Agent) watchAddress(ip net.IP, done <-chan struct{}) error {
	want := ip.String()
	tick := time.NewTicker(a.cfg.NetworkCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-done:
			return nil
		case <-tick.C:
			set, ok := a.addrSet()
			if ok && !contains(set, want) {
				return fmt.Errorf("%w: %s is no longer a local address", errNetworkChanged, want)
			}
		}
	}
}

func contains(set, ip string) bool {
	for _, s := range strings.Split(set, ",") {
		if s == ip {
			return true
		}
	}
	return false
}

// waitToReconnect waits d before the next attempt, and returns early (true)
// when the machine's addresses change: a new network is worth trying now.
func (a *Agent) waitToReconnect(ctx context.Context, d time.Duration) (changed bool, err error) {
	before, known := a.addrSet()
	timer := time.NewTimer(d)
	defer timer.Stop()
	tick := time.NewTicker(a.cfg.NetworkCheckInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return false, ctx.Err()
		case <-timer.C:
			return false, nil
		case <-tick.C:
			now, ok := a.addrSet()
			if !ok {
				continue
			}
			if !known {
				before, known = now, true
				continue
			}
			if now != before {
				return true, nil
			}
		}
	}
}
