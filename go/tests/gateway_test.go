package tests

import (
	"crypto/ed25519"
	"crypto/rand"
	"strconv"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

func newSSHKey(t *testing.T) ssh.Signer {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func startGateway(t *testing.T, opts relayOpts) *relayEnv {
	t.Helper()
	opts.gateway = newSSHKey(t)
	if opts.ports == 0 && opts.portMin == 0 {
		opts.ports = 3
	}
	return startRelayWith(t, opts)
}

func grant(t *testing.T, env *relayEnv, name string, key ssh.Signer, tunnels ...string) {
	t.Helper()
	k, err := auth.NewGatewayKey(name, string(ssh.MarshalAuthorizedKey(key.PublicKey())), tunnels)
	if err != nil {
		t.Fatal(err)
	}
	if err := env.store.AddGatewayKey(k); err != nil {
		t.Fatal(err)
	}
}

func gatewayClient(t *testing.T, env *relayEnv, key ssh.Signer) (*ssh.Client, error) {
	t.Helper()
	c, err := ssh.Dial("tcp", env.srv.GatewayAddr(), &ssh.ClientConfig{
		User: "gw", Auth: []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.FixedHostKey(env.opts.gateway.PublicKey()), Timeout: 5 * time.Second,
	})
	if err == nil {
		t.Cleanup(func() { c.Close() })
	}
	return c, err
}

// viaGateway sends msg through a direct-tcpip channel (what ssh -J opens)
// to target and returns the echo.
func viaGateway(c *ssh.Client, target, msg string) (string, error) {
	conn, err := c.Dial("tcp", target)
	if err != nil {
		return "", err
	}
	defer conn.Close()
	conn.Write([]byte(msg))
	buf := make([]byte, len(msg))
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	n, err := conn.Read(buf)
	for err == nil && n < len(buf) {
		var m int
		m, err = conn.Read(buf[n:])
		n += m
	}
	return string(buf[:n]), err
}

func TestSSHGatewayForwardsToTunnels(t *testing.T) {
	env := startGateway(t, relayOpts{})
	ra := startAgent(t, env, agent.TunnelConfig{Name: "homebox", Type: sshType, Target: startEchoServer(t)})
	key := newSSHKey(t)
	grant(t, env, "alice", key, "home*")
	c, err := gatewayClient(t, env, key)
	if err != nil {
		t.Fatal(err)
	}
	port := ra.agent.Endpoints()[0].GetPublicPort()
	for _, target := range []string{"homebox:22", "homebox." + baseDomain + ":22", "homebox:" + strconv.Itoa(int(port))} {
		if got, err := viaGateway(c, target, "hello "+target); err != nil || got != "hello "+target {
			t.Fatalf("%s: %q %v", target, got, err)
		}
	}
	// No shells, no exec: the gateway only forwards.
	if _, err := c.NewSession(); err == nil {
		t.Fatal("the gateway opened a session channel")
	}
	if _, err := viaGateway(c, "homebox:8080", "x"); err == nil {
		t.Fatal("the gateway forwarded to an arbitrary port")
	}
}

func TestSSHGatewayRefusesUnknownAndUngrantedKeys(t *testing.T) {
	env := startGateway(t, relayOpts{})
	startAgent(t, env,
		agent.TunnelConfig{Name: "homebox", Type: sshType, Target: startEchoServer(t)},
		agent.TunnelConfig{Name: "prod", Type: sshType, Target: startEchoServer(t)})
	if _, err := gatewayClient(t, env, newSSHKey(t)); err == nil {
		t.Fatal("an unregistered key logged in")
	}
	key := newSSHKey(t)
	grant(t, env, "alice", key, "homebox")
	c, err := gatewayClient(t, env, key)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := viaGateway(c, "prod:22", "x"); err == nil || !strings.Contains(err.Error(), "isn't granted") {
		t.Fatalf("ungranted tunnel: %v", err)
	}
	if _, err := viaGateway(c, "nothing:22", "x"); err == nil {
		t.Fatal("forwarded to a tunnel that doesn't exist")
	}
	// Removing the key stops new forwards on an open connection.
	if err := env.store.DeleteGatewayKey("alice"); err != nil {
		t.Fatal(err)
	}
	if _, err := viaGateway(c, "homebox:22", "x"); err == nil {
		t.Fatal("a removed key could still forward")
	}
}

func TestSSHGatewayAccessTokenTunnelsNeedExplicitGrant(t *testing.T) {
	env := startGateway(t, relayOpts{})
	startAgent(t, env, agent.TunnelConfig{Name: "vault", Type: sshType, Target: startEchoServer(t), AccessToken: "sesame"})
	wild, exact := newSSHKey(t), newSSHKey(t)
	grant(t, env, "wild", wild, "*")
	grant(t, env, "exact", exact, "vault")
	cw, _ := gatewayClient(t, env, wild)
	if _, err := viaGateway(cw, "vault:22", "x"); err == nil {
		t.Fatal("a wildcard grant reached an access-token tunnel")
	}
	ce, _ := gatewayClient(t, env, exact)
	if got, err := viaGateway(ce, "vault:22", "ok"); err != nil || got != "ok" {
		t.Fatalf("explicit grant: %q %v", got, err)
	}
}

func TestSSHGatewayAppliesIPLists(t *testing.T) {
	env := startGateway(t, relayOpts{})
	startAgent(t, env, agent.TunnelConfig{Name: "lan", Type: sshType, Target: startEchoServer(t), AllowIPs: []string{"10.0.0.0/8"}})
	key := newSSHKey(t)
	grant(t, env, "alice", key, "*")
	c, _ := gatewayClient(t, env, key)
	if _, err := viaGateway(c, "lan:22", "x"); err == nil {
		t.Fatal("the gateway ignored the tunnel's allow list")
	}
}

func TestGatewayKeyAdminAndValidation(t *testing.T) {
	env := startGateway(t, relayOpts{})
	socket := startAdmin(t, env)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(newSSHKey(t).PublicKey())))
	if out := mustAdmin(t, socket, "gateway-key", "add", "--name", "bob", "--key", pub+" bob@laptop", "--tunnels", "a,b*"); !strings.Contains(out, "SHA256:") {
		t.Fatalf("add: %s", out)
	}
	if _, err := adminCmd(t, socket, "gateway-key", "add", "--name", "bob2", "--key", pub, "--tunnels", "a"); err == nil {
		t.Fatal("the same public key was registered twice")
	}
	if _, err := adminCmd(t, socket, "gateway-key", "add", "--name", "x", "--key", "ssh-rsa notakey", "--tunnels", "a"); err == nil {
		t.Fatal("a malformed key was accepted")
	}
	if _, err := adminCmd(t, socket, "gateway-key", "add", "--name", "y", "--key", pub, "--tunnels", "["); err == nil {
		t.Fatal("a bad pattern was accepted")
	}
	if out := mustAdmin(t, socket, "gateway-key", "list"); !strings.Contains(out, "bob") || !strings.Contains(out, "a,b*") {
		t.Fatalf("list:\n%s", out)
	}
	mustAdmin(t, socket, "gateway-key", "remove", "bob")
	if _, err := adminCmd(t, socket, "gateway-key", "remove", "bob"); err == nil {
		t.Fatal("removed a key twice")
	}
}
