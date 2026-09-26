package tests

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/agent"
	"github.com/saichler/l8tunnel/go/tunnel/protocol"
	"github.com/saichler/l8tunnel/go/tunnel/transport"
	"github.com/saichler/l8tunnel/go/types/tun"
)

// The KIND deployment (k8s/l8tunnel-kind.yaml): base domain and each
// relay's NodePorts on the host.
const (
	kindBase       = "tunnel.kind.test"
	kindControl    = "connect." + kindBase
	kindRelay0TLS  = "localhost:30443"
	kindRelay0Strm = "localhost:30444"
	kindRelay1TLS  = "localhost:31443"
	kindRelay1Strm = "localhost:31444"
	kindRelay1Gw   = "localhost:31222"
	kindRelay0     = "l8tunnel-relay-0"
	kindRelay1     = "l8tunnel-relay-1"
)

// kubectl runs kubectl against the KIND cluster.
func kubectl(t *testing.T, args ...string) string {
	t.Helper()
	out, err := exec.Command("kubectl", append([]string{"--context", "kind-l8tunnel", "-n", "l8tunnel"}, args...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("kubectl %s: %v\n%s", strings.Join(args, " "), err, out)
	}
	return string(out)
}

// forwardKey is the cluster secret that signs edge/relay PROXY headers.
func forwardKey(t *testing.T) []byte {
	t.Helper()
	b64 := kubectl(t, "get", "secret", "l8tunnel-cluster", "-o", "jsonpath={.data.forward-key}")
	raw, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatal(err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(raw)))
	if err != nil {
		t.Fatal(err)
	}
	return key
}

// kindCA is a CA and a tunnel certificate for the KIND base domain.
type kindCA struct {
	caFile          string
	certPEM, keyPEM []byte
}

func newKindCA(t *testing.T) *kindCA {
	t.Helper()
	caKey, leafKey := mustKey(t), mustKey(t)
	caTmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "kind test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 3, 0), IsCA: true,
		KeyUsage: x509.KeyUsageCertSign, BasicConstraintsValid: true}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	caCert, _ := x509.ParseCertificate(caDER)
	leafTmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: kindControl},
		DNSNames: []string{kindBase, "*." + kindBase}, NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().AddDate(0, 2, 0),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(leafKey)
	ca := &kindCA{caFile: filepath.Join(t.TempDir(), "ca.pem"),
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		keyPEM:  pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})}
	writePEM(t, ca.caFile, "CERTIFICATE", caDER)
	return ca
}

func (ca *kindCA) pool(t *testing.T) *x509.CertPool {
	t.Helper()
	data, err := os.ReadFile(ca.caFile)
	if err != nil {
		t.Fatal(err)
	}
	p := x509.NewCertPool()
	p.AppendCertsFromPEM(data)
	return p
}

// installTunnelCert uploads the certificate on the TUNNEL_BASE domain and
// waits until both relays serve it.
func installTunnelCert(t *testing.T, c *kindClient) *kindCA {
	t.Helper()
	ca := newKindCA(t)
	var base *tun.EdgeDomain
	waitUntil(t, 60*time.Second, "tunnel base domain", func() bool {
		d := domainsNamed(t, c, kindBase)
		if len(d) == 1 {
			base = d[0]
		}
		return base != nil
	})
	base.CertStoragePath = upload(t, c, uniqueName("tunnel")+".crt", ca.certPEM).StoragePath
	base.KeyStoragePath = upload(t, c, uniqueName("tunnel")+".key", ca.keyPEM).StoragePath
	c.mustDo(put, common.AreaEdge, common.DomainService, base, nil)
	for _, addr := range []string{kindRelay0TLS, kindRelay1TLS} {
		waitUntil(t, 90*time.Second, "relay "+addr+" serving the tunnel certificate", func() bool {
			conn, err := tls.Dial("tcp", addr, &tls.Config{ServerName: kindControl, RootCAs: ca.pool(t), NextProtos: []string{protocol.ALPN}})
			if err != nil {
				return false
			}
			conn.Close()
			return true
		})
	}
	return ca
}

// kindAgent runs an agent against one relay's NodePort.
func kindAgent(t *testing.T, ca *kindCA, relayAddr, token, agentID string, tunnels ...agent.TunnelConfig) *runningAgent {
	t.Helper()
	tlsCfg, err := transport.ClientTLSConfig(kindControl, ca.caFile)
	if err != nil {
		t.Fatal(err)
	}
	a, err := agent.New(agent.Config{RelayAddr: relayAddr, TLS: tlsCfg, Token: token, AgentID: agentID, Version: "test",
		Proxy: transport.ProxyNone, ReconnectMin: 100 * time.Millisecond, ReconnectMax: 500 * time.Millisecond,
		Logger: testLogger(), Tunnels: tunnels})
	if err != nil {
		t.Fatal(err)
	}
	return runAgent(t, a)
}

// edgeStream opens a stream as the edge does: a PROXY header signed with
// the cluster key, naming the tunnel, from client.
func edgeStream(t *testing.T, key []byte, addr, tunnel, client string) net.Conn {
	t.Helper()
	conn, err := net.DialTimeout("tcp", addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	src := net.TCPAddrFromAddrPort(mustAddrPort(t, client))
	tlvs := transport.SignedTLVs(key, tunnel, src.String(), time.Now())
	if err := transport.WriteProxyHeader(conn, src, conn.RemoteAddr(), tlvs...); err != nil {
		t.Fatal(err)
	}
	return conn
}

// echoes reports whether conn echoes a payload back.
func echoes(conn net.Conn, payload string) bool {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(10 * time.Second))
	if _, err := conn.Write([]byte(payload)); err != nil {
		return false
	}
	buf := make([]byte, len(payload))
	n, _ := conn.Read(buf)
	return string(buf[:n]) == payload
}

// relayHTTPSClient reaches every host through one relay.
func relayHTTPSClient(t *testing.T, ca *kindCA, relayAddr string) *http.Client {
	t.Helper()
	tr := &http.Transport{TLSClientConfig: &tls.Config{RootCAs: ca.pool(t)},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var d net.Dialer
			return d.DialContext(ctx, "tcp", relayAddr)
		}}
	t.Cleanup(tr.CloseIdleConnections)
	return &http.Client{Transport: tr, Timeout: 30 * time.Second}
}

// liveTunnel returns the live record of a tunnel, or nil.
func liveTunnel(t *testing.T, c *kindClient, name string) *tun.TunLiveTunnel {
	t.Helper()
	list := &tun.TunLiveTunnelList{}
	if err := c.query(common.AreaLive, common.LiveService, "select * from TunLiveTunnel where name="+name, list); err != nil {
		t.Fatal(err)
	}
	for _, r := range list.List {
		if r.Name == name {
			return r
		}
	}
	return nil
}

// liveAgent returns the live record of an agent, or nil.
func liveAgent(t *testing.T, c *kindClient, id string) *tun.TunAgent {
	t.Helper()
	list := &tun.TunAgentList{}
	if err := c.query(common.AreaLive, common.AgentService, "select * from TunAgent where agentId="+id, list); err != nil {
		t.Fatal(err)
	}
	for _, r := range list.List {
		if r.AgentId == id {
			return r
		}
	}
	return nil
}

func liveRelay(t *testing.T, c *kindClient, id string) *tun.TunRelay {
	t.Helper()
	list := &tun.TunRelayList{}
	if err := c.query(common.AreaLive, common.RelayService, "select * from TunRelay where relayId="+id, list); err != nil {
		t.Fatal(err)
	}
	for _, r := range list.List {
		if r.RelayId == id {
			return r
		}
	}
	return nil
}

func ctl(t *testing.T, c *kindClient, cmd *tun.TunCtlCommand) {
	t.Helper()
	c.mustDo(post, common.AreaLive, common.CtlService, cmd, nil)
}

func mustAddrPort(t *testing.T, s string) netip.AddrPort {
	t.Helper()
	ap, err := netip.ParseAddrPort(s)
	if err != nil {
		t.Fatal(err)
	}
	return ap
}
