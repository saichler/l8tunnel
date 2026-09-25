package agent

import (
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/protocol"
)

// tunnelStats counts a tunnel's connections and bytes (bytes are added
// when a connection ends).
type tunnelStats struct {
	active   atomic.Int64
	total    atomic.Int64
	bytesIn  atomic.Int64 // client -> service
	bytesOut atomic.Int64 // service -> client
}

// connState is guarded by Agent.mu.
type connState struct {
	connected  bool
	since      time.Time
	lastError  string
	reconnects int
}

// Status is a snapshot of the agent for "l8tunnel-agent status".
type Status struct {
	AgentID        string         `json:"agent_id"`
	Relay          string         `json:"relay"`
	Connected      bool           `json:"connected"`
	ConnectedSince time.Time      `json:"connected_since,omitempty"`
	LastError      string         `json:"last_error,omitempty"`
	Reconnects     int            `json:"reconnects"`
	Tunnels        []TunnelStatus `json:"tunnels"`
}

// TunnelStatus describes one configured tunnel.
type TunnelStatus struct {
	Name          string `json:"name"`
	Type          string `json:"type"`
	Target        string `json:"target"`
	PublicAddress string `json:"public_address,omitempty"`
	Hostname      string `json:"hostname,omitempty"`
	ActiveConns   int64  `json:"active_conns"`
	TotalConns    int64  `json:"total_conns"`
	BytesIn       int64  `json:"bytes_in"`
	BytesOut      int64  `json:"bytes_out"`
}

// Status returns a snapshot of the connection and every tunnel.
func (a *Agent) Status() Status {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := Status{
		AgentID:    a.cfg.AgentID,
		Relay:      a.cfg.RelayAddr,
		Connected:  a.state.connected,
		LastError:  a.state.lastError,
		Reconnects: a.state.reconnects,
		Tunnels:    make([]TunnelStatus, 0, len(a.cfg.Tunnels)),
	}
	if a.state.connected {
		st.ConnectedSince = a.state.since
	}
	for i, t := range a.cfg.Tunnels {
		ts := TunnelStatus{
			Name:        a.names[i],
			Type:        protocol.TunnelTypeName(t.Type),
			Target:      t.targetString(),
			ActiveConns: a.stats[i].active.Load(),
			TotalConns:  a.stats[i].total.Load(),
			BytesIn:     a.stats[i].bytesIn.Load(),
			BytesOut:    a.stats[i].bytesOut.Load(),
		}
		if a.state.connected && i < len(a.endpoints) {
			ts.PublicAddress = a.endpoints[i].GetPublicAddress()
			ts.Hostname = a.endpoints[i].GetHostname()
		}
		st.Tunnels = append(st.Tunnels, ts)
	}
	return st
}

// setDisconnected records why a session ended.
func (a *Agent) setDisconnected(err error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state.connected {
		a.state.reconnects++
	}
	a.state.connected = false
	if err != nil {
		a.state.lastError = err.Error()
	}
}
