package agent

import (
	"context"
	"fmt"
	"net"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/pipe"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

const dialTimeout = 10 * time.Second

// serveStream reads a stream's header, dials the tunnel's local target and
// pipes the two together. The relay only names a tunnel ID; the agent
// dials nothing but its own configured targets.
func (a *Agent) serveStream(ctx context.Context, stream *transport.Stream) {
	open, err := readStreamOpen(stream)
	if err != nil {
		a.log.Warn("bad stream from relay", "error", err)
		stream.Close()
		return
	}
	log := a.log.With("client", open.GetClientAddr())
	target := a.targetFor(open.GetTunnelId())
	if target == "" {
		log.Warn("stream for unknown tunnel", "tunnel_id", open.GetTunnelId())
		stream.Close()
		return
	}

	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		log.Warn("dial target failed", "target", target, "error", err)
		stream.Close()
		return
	}
	res := pipe.Join(stream, conn.(*net.TCPConn))
	log.Debug("stream closed", "target", target, "bytes_in", res.AtoB, "bytes_out", res.BtoA, "error", res.Err)
}

func readStreamOpen(stream *transport.Stream) (*l8tunnel.StreamOpen, error) {
	if err := stream.SetReadDeadline(time.Now().Add(handshakeTimeout)); err != nil {
		return nil, err
	}
	open := &l8tunnel.StreamOpen{}
	if err := protocol.ReadMessage(stream, open); err != nil {
		return nil, fmt.Errorf("read stream header: %w", err)
	}
	if err := stream.SetReadDeadline(time.Time{}); err != nil {
		return nil, err
	}
	return open, nil
}
