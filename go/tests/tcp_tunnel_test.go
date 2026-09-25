package tests

import (
	"bytes"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/types/l8tunnel"
)

var tcpType = l8tunnel.TunnelType_TUNNEL_TYPE_TCP

// roundTrip sends payload through addr, half-closes, and returns the echo.
func roundTrip(addr string, payload []byte) ([]byte, error) {
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	if err := conn.SetDeadline(time.Now().Add(30 * time.Second)); err != nil {
		return nil, err
	}
	writeErr := make(chan error, 1)
	go func() {
		_, err := conn.Write(payload)
		if err == nil {
			err = conn.(*net.TCPConn).CloseWrite()
		}
		writeErr <- err
	}()
	got, err := io.ReadAll(conn)
	if err != nil {
		return nil, err
	}
	return got, <-writeErr
}

func TestTCPTunnelRoundTripLargePayload(t *testing.T) {
	env := startRelay(t, 5)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "echo", Type: tcpType, Target: startEchoServer(t)})

	eps := ra.agent.Endpoints()
	if len(eps) != 1 {
		t.Fatalf("got %d endpoints, want 1", len(eps))
	}
	ep := eps[0]
	if ep.GetName() != "echo" || ep.GetPublicPort() < uint32(env.portMin) || ep.GetPublicPort() > uint32(env.portMax) {
		t.Fatalf("unexpected endpoint %v (range %d-%d)", ep, env.portMin, env.portMax)
	}
	if want := fmt.Sprintf("localhost:%d", ep.GetPublicPort()); ep.GetPublicAddress() != want {
		t.Fatalf("public address = %q, want %q", ep.GetPublicAddress(), want)
	}

	payload := make([]byte, 8<<20)
	rand.Read(payload)
	got, err := roundTrip(publicAddr(ep.GetPublicPort()), payload)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("echo mismatch: sent %d bytes, got %d", len(payload), len(got))
	}
}

func TestSSHTunnelConcurrentConnections(t *testing.T) {
	env := startRelay(t, 5)
	ra := startAgent(t, env, agent.TunnelConfig{
		Name: "homebox", Type: l8tunnel.TunnelType_TUNNEL_TYPE_SSH, Target: startEchoServer(t),
	})
	addr := publicAddr(ra.agent.Endpoints()[0].GetPublicPort())

	const conns = 50
	var wg sync.WaitGroup
	errs := make(chan error, conns)
	for i := 0; i < conns; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			payload := []byte(fmt.Sprintf("connection %d says hello", i))
			got, err := roundTrip(addr, payload)
			if err == nil && !bytes.Equal(got, payload) {
				err = fmt.Errorf("connection %d: got %q", i, got)
			}
			errs <- err
		}(i)
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
}

func TestMultipleTunnelsFixedAndAllocatedPorts(t *testing.T) {
	env := startRelay(t, 5)
	fixed := uint32(env.portMax)
	ra := startAgent(t, env,
		agent.TunnelConfig{Name: "fixed", Type: tcpType, Target: startEchoServer(t), PublicPort: fixed},
		agent.TunnelConfig{Type: tcpType, Target: startEchoServer(t)},
	)
	eps := ra.agent.Endpoints()
	if len(eps) != 2 {
		t.Fatalf("got %d endpoints, want 2", len(eps))
	}
	if eps[0].GetPublicPort() != fixed {
		t.Fatalf("fixed tunnel got port %d, want %d", eps[0].GetPublicPort(), fixed)
	}
	if eps[1].GetName() == "" || eps[1].GetPublicPort() == fixed {
		t.Fatalf("allocated tunnel got unexpected endpoint %v", eps[1])
	}
	for _, ep := range eps {
		got, err := roundTrip(publicAddr(ep.GetPublicPort()), []byte(ep.GetName()))
		if err != nil || string(got) != ep.GetName() {
			t.Fatalf("tunnel %s: got %q, err %v", ep.GetName(), got, err)
		}
	}
}

func TestAgentDisconnectFreesNameAndPort(t *testing.T) {
	env := startRelay(t, 1)
	target := startEchoServer(t)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "reuse", Type: tcpType, Target: target})
	port := ra.agent.Endpoints()[0].GetPublicPort()

	ra.cancel()
	select {
	case err := <-ra.done:
		ra.done <- err
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop after cancel")
	}
	waitUntil(t, 5*time.Second, "public port to close", func() bool {
		conn, err := net.DialTimeout("tcp", publicAddr(port), time.Second)
		if err != nil {
			return true
		}
		conn.Close()
		return false
	})

	// The same name and the relay's only port are available again.
	ra2 := startAgent(t, env, agent.TunnelConfig{Name: "reuse", Type: tcpType, Target: target})
	if got := ra2.agent.Endpoints()[0].GetPublicPort(); got != port {
		t.Fatalf("second agent got port %d, want %d", got, port)
	}
}

func TestTargetDownClosesPublicConnection(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "down", Type: tcpType, Target: unusedAddr(t)})

	conn, err := net.DialTimeout("tcp", publicAddr(ra.agent.Endpoints()[0].GetPublicPort()), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	n, err := conn.Read(make([]byte, 1))
	var netErr net.Error
	if n != 0 || (errors.As(err, &netErr) && netErr.Timeout()) {
		t.Fatalf("expected the connection to be closed, got n=%d err=%v", n, err)
	}
}

func TestRelayShutdownEndsAgentSession(t *testing.T) {
	env := startRelay(t, 1)
	ra := startAgent(t, env, agent.TunnelConfig{Name: "bye", Type: tcpType, Target: startEchoServer(t)})

	if err := env.srv.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-ra.done:
		ra.done <- err
		if err == nil {
			t.Fatal("agent Run returned nil after the relay shut down")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not notice the relay shutting down")
	}
}

func waitUntil(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}
