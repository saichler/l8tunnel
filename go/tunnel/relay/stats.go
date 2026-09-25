package relay

import (
	"sync"
	"sync/atomic"

	"github.com/saichler/l8tunnel/go/tunnel/transport"
)

// tunnelStats counts a tunnel's streams (one per public connection, or
// per pooled HTTP connection) and bytes.
type tunnelStats struct {
	active   atomic.Int64
	total    atomic.Int64
	bytesIn  atomic.Int64 // client -> service
	bytesOut atomic.Int64 // service -> client
}

func (s *tunnelStats) track(stream *transport.Stream) *countedStream {
	s.active.Add(1)
	s.total.Add(1)
	return &countedStream{Stream: stream, stats: s}
}

// countedStream counts bytes through a stream. transport.Stream has no
// WriteTo/ReadFrom, so embedding it doesn't let io.Copy bypass the counts.
type countedStream struct {
	*transport.Stream
	stats *tunnelStats
	once  sync.Once
}

func (c *countedStream) Read(p []byte) (int, error) {
	n, err := c.Stream.Read(p)
	c.stats.bytesOut.Add(int64(n))
	return n, err
}

func (c *countedStream) Write(p []byte) (int, error) {
	n, err := c.Stream.Write(p)
	c.stats.bytesIn.Add(int64(n))
	return n, err
}

func (c *countedStream) Close() error {
	c.once.Do(func() { c.stats.active.Add(-1) })
	return c.Stream.Close()
}
