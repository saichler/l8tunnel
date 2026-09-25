package agent

import (
	"context"
	"crypto/tls"
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
	t, stats, ok := a.tunnelFor(open.GetTunnelId())
	if !ok {
		log.Warn("stream for unknown tunnel", "tunnel_id", open.GetTunnelId())
		stream.Close()
		return
	}
	conn, err := dialTarget(ctx, t)
	if err != nil {
		log.Warn("dial target failed", "target", t.targetString(), "error", err)
		stream.Close()
		return
	}
	stats.active.Add(1)
	stats.total.Add(1)
	res := pipe.Join(stream, conn)
	stats.active.Add(-1)
	stats.bytesIn.Add(res.AtoB)
	stats.bytesOut.Add(res.BtoA)
	log.Debug("stream closed", "target", t.targetString(), "bytes_in", res.AtoB, "bytes_out", res.BtoA, "error", res.Err)
}

// dialTarget connects to a tunnel's local target, over TLS when the
// target is HTTPS.
func dialTarget(ctx context.Context, t TunnelConfig) (pipe.Conn, error) {
	dialer := &net.Dialer{Timeout: dialTimeout}
	conn, err := dialer.DialContext(ctx, "tcp", t.Target)
	if err != nil {
		return nil, err
	}
	tcp := conn.(*net.TCPConn)
	if !t.TargetTLS {
		return tcp, nil
	}
	host, _, err := net.SplitHostPort(t.Target)
	if err != nil {
		tcp.Close()
		return nil, err
	}
	tconn := tls.Client(tcp, &tls.Config{
		ServerName:         host,
		InsecureSkipVerify: t.InsecureSkipVerify,
		NextProtos:         []string{"http/1.1"},
	})
	hctx, cancel := context.WithTimeout(ctx, dialTimeout)
	defer cancel()
	if err := tconn.HandshakeContext(hctx); err != nil {
		tcp.Close()
		return nil, fmt.Errorf("TLS handshake with %s: %w", t.Target, err)
	}
	return tconn, nil
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
