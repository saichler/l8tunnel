package tests

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
)

// PRD §8 performance targets. The scale tests run in the normal suite;
// throughput and latency are benchmarks:
//
//	go test ./tests/ -run '^$' -bench . -benchtime 3x

// TestScale1000ConcurrentConnections holds 1,000 connections open through
// one tunnel at the same time, then checks each one still echoes.
func TestScale1000ConcurrentConnections(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "many", Type: tcpType, Target: startEchoServer(t)})
	addr := publicAddr(ra.agent.Endpoints()[0].GetPublicPort())

	const n = 1000
	conns := make([]net.Conn, n)
	for i := range conns {
		c, err := net.DialTimeout("tcp", addr, 10*time.Second)
		if err != nil {
			t.Fatalf("connection %d: %v", i, err)
		}
		defer c.Close()
		conns[i] = c
	}
	waitUntil(t, 10*time.Second, "all streams to be open", func() bool {
		st := env.srv.Status()
		return len(st.Sessions) == 1 && st.Sessions[0].Tunnels[0].ActiveConns == n
	})

	var wg sync.WaitGroup
	errs := make(chan error, n)
	for i, c := range conns {
		wg.Add(1)
		go func(i int, c net.Conn) {
			defer wg.Done()
			msg := []byte(fmt.Sprintf("conn-%04d", i))
			c.SetDeadline(time.Now().Add(20 * time.Second))
			if _, err := c.Write(msg); err != nil {
				errs <- err
				return
			}
			got := make([]byte, len(msg))
			if _, err := io.ReadFull(c, got); err != nil || !bytes.Equal(got, msg) {
				errs <- fmt.Errorf("conn %d: got %q, %v", i, got, err)
			}
		}(i, c)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}

// TestScale100Agents registers 100 agents on one relay and uses each.
func TestScale100Agents(t *testing.T) {
	const n = 100
	env := startRelay(t, n)
	target := startEchoServer(t)
	agents := make([]*runningAgent, n)
	for i := range agents {
		agents[i] = runAgent(t, newAgent(t, env, testToken, agent.TunnelConfig{Name: fmt.Sprintf("a%03d", i), Type: tcpType, Target: target}))
	}
	for i, ra := range agents {
		select {
		case <-ra.agent.Ready():
		case err := <-ra.done:
			t.Fatalf("agent %d stopped: %v", i, err)
		case <-time.After(30 * time.Second):
			t.Fatalf("agent %d not ready", i)
		}
	}
	if got := len(env.srv.Status().Sessions); got != n {
		t.Fatalf("%d sessions, want %d", got, n)
	}
	for i, ra := range agents {
		msg := []byte(fmt.Sprintf("agent-%03d", i))
		if got, err := roundTrip(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), msg); err != nil || !bytes.Equal(got, msg) {
			t.Fatalf("agent %d: %q %v", i, got, err)
		}
	}
}

// startSinkServer reads everything from each connection and replies with
// one byte when the client half-closes.
func startSinkServer(tb testing.TB) string {
	tb.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		tb.Fatal(err)
	}
	tb.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(io.Discard, c)
				c.Write([]byte{1})
			}()
		}
	}()
	return ln.Addr().String()
}

// pushBytes sends size bytes to addr and waits for the sink's reply.
func pushBytes(addr string, size int64) error {
	c, err := net.Dial("tcp", addr)
	if err != nil {
		return err
	}
	defer c.Close()
	chunk := make([]byte, 256<<10)
	for sent := int64(0); sent < size; sent += int64(len(chunk)) {
		if _, err := c.Write(chunk); err != nil {
			return err
		}
	}
	c.(*net.TCPConn).CloseWrite()
	_, err = io.ReadFull(c, make([]byte, 1))
	return err
}

func benchThroughput(b *testing.B, parallel int) {
	env := startRelay(b, 1)
	ra := startAgent(b, env, agent.TunnelConfig{Name: "bulk", Type: tcpType, Target: startSinkServer(b)})
	addr := publicAddr(ra.agent.Endpoints()[0].GetPublicPort())
	const perConn = 256 << 20 // 256 MiB per connection per iteration
	b.SetBytes(perConn * int64(parallel))
	b.ResetTimer()
	start := time.Now()
	for i := 0; i < b.N; i++ {
		var wg sync.WaitGroup
		errs := make(chan error, parallel)
		for p := 0; p < parallel; p++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				errs <- pushBytes(addr, perConn)
			}()
		}
		wg.Wait()
		close(errs)
		for err := range errs {
			if err != nil {
				b.Fatal(err)
			}
		}
	}
	elapsed := time.Since(start).Seconds()
	b.ReportMetric(float64(perConn*int64(parallel)*int64(b.N)*8)/elapsed/1e6, "Mbit/s")
}

func BenchmarkThroughput1Conn(b *testing.B)  { benchThroughput(b, 1) }
func BenchmarkThroughput8Conns(b *testing.B) { benchThroughput(b, 8) }

// BenchmarkAddedLatency compares 1-byte round trips through the tunnel
// with round trips straight to the same echo server, on one connection
// each. The relay and agent run in-process on loopback, so this measures
// the processing they add, not network latency.
func BenchmarkAddedLatency(b *testing.B) {
	env := startRelay(b, 1)
	target := startEchoServer(b)
	ra := startAgent(b, env, agent.TunnelConfig{Name: "lat", Type: tcpType, Target: target})
	measure := func(addr string, rounds int) time.Duration {
		c, err := net.Dial("tcp", addr)
		if err != nil {
			b.Fatal(err)
		}
		defer c.Close()
		c.(*net.TCPConn).SetNoDelay(true)
		buf := make([]byte, 1)
		samples := make([]time.Duration, rounds)
		for i := range samples {
			start := time.Now()
			if _, err := c.Write(buf); err != nil {
				b.Fatal(err)
			}
			if _, err := io.ReadFull(c, buf); err != nil {
				b.Fatal(err)
			}
			samples[i] = time.Since(start)
		}
		sort.Slice(samples, func(i, j int) bool { return samples[i] < samples[j] })
		return samples[len(samples)/2] // median
	}
	const rounds = 2000
	b.ResetTimer()
	var direct, tunneled time.Duration
	for i := 0; i < b.N; i++ {
		direct = measure(target, rounds)
		tunneled = measure(publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), rounds)
	}
	b.ReportMetric(float64(direct.Microseconds()), "direct-µs")
	b.ReportMetric(float64(tunneled.Microseconds()), "tunneled-µs")
	b.ReportMetric(float64((tunneled - direct).Microseconds()), "added-µs")
}
