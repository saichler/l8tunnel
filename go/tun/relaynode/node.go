package relaynode

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/auth"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/relay"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"golang.org/x/crypto/ssh"
)

const (
	heartbeatInterval = 5 * time.Second
	resyncInterval    = time.Minute
	snapshotDir       = "/data/l8tunnel"
)

// snapshotFile is this relay's accounts snapshot. It's named per pod:
// relays that share /data (local mode's hostPath) must not overwrite
// each other's file.
func snapshotFile(id string) string {
	return filepath.Join(snapshotDir, "accounts-"+id+".json")
}

// Node is a relay running in the cluster.
type Node struct {
	vnic      ifs.IVNic
	relayID   string
	podIP     string
	version   string
	srv       *relay.Server
	accounts  *accounts
	link      *link
	cert      *certs.Dynamic
	startedAt time.Time

	certFingerprint string
	refreshPending  atomic.Bool
}

// Run starts the relay and blocks until ctx ends.
func Run(ctx context.Context, vnic ifs.IVNic, version string, logger *slog.Logger) error {
	c := common.Cluster()
	n := &Node{vnic: vnic, relayID: os.Getenv("POD_NAME"), podIP: os.Getenv("POD_IP"), version: version,
		cert: &certs.Dynamic{}, startedAt: time.Now()}
	if n.relayID == "" || n.podIP == "" {
		return fmt.Errorf("POD_NAME and POD_IP must be set (the pod's name and IP)")
	}
	key, err := common.ForwardKey()
	if err != nil {
		return err
	}
	n.link = &link{vnic: vnic, relayID: n.relayID, key: key, live: common.NewLiveView(vnic, ownersTTL)}
	// The ops endpoints come up first, so liveness probes pass while the
	// relay waits for the management backend.
	opsLn, err := net.Listen("tcp", ":"+strconv.Itoa(c.Relay.Ops))
	if err != nil {
		return fmt.Errorf("ops listener: %w", err)
	}
	ops := &opsHandler{}
	go admin.Serve(ctx, opsLn, ops, logger)
	n.accounts = newAccounts(vnic, snapshotFile(n.relayID))
	if err := n.loadAccounts(ctx, logger); err != nil {
		return err
	}
	if err := n.loadCert(); err != nil {
		logger.Warn("no tunnel certificate yet; TLS handshakes fail until one is uploaded", "error", err)
	}
	cfg, err := n.relayConfig(logger)
	if err != nil {
		return err
	}
	if n.srv, err = relay.New(cfg); err != nil {
		return err
	}
	if err := n.srv.Start(); err != nil {
		return err
	}
	n.activateCtl()
	ops.set(n.srv.OpsHandler())
	n.announce()
	go n.loop(ctx)
	<-ctx.Done()
	n.srv.Drain(0)
	return n.srv.Close()
}

// loadAccounts gets the agent credentials: from the backend, or the
// snapshot when the backend is down. Without a snapshot it keeps trying
// (a fresh cluster starts the backend and the relays together).
func (n *Node) loadAccounts(ctx context.Context, logger *slog.Logger) error {
	for {
		err := n.accounts.refresh()
		if err == nil {
			return nil
		}
		if n.accounts.load() == nil {
			logger.Warn("management backend unreachable; using the credentials snapshot", "error", err)
			return nil
		}
		logger.Warn("waiting for the management backend", "error", err)
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(5 * time.Second):
		}
	}
}

func (n *Node) relayConfig(logger *slog.Logger) (relay.Config, error) {
	c := common.Cluster()
	rules := c.Rules()
	caCert, err := os.ReadFile(c.AgentCA.Cert)
	if err != nil {
		return relay.Config{}, fmt.Errorf("agent CA: %w", err)
	}
	caKey, err := os.ReadFile(c.AgentCA.Key)
	if err != nil {
		return relay.Config{}, fmt.Errorf("agent CA: %w", err)
	}
	ca, err := auth.LoadAgentCA(caCert, caKey)
	if err != nil {
		return relay.Config{}, err
	}
	cfg := relay.Config{
		ControlAddr: ":" + strconv.Itoa(c.Relay.TLS), StreamAddr: ":" + strconv.Itoa(c.Relay.Stream),
		PublicHTTPSPort: c.Public.HTTPS, TLS: n.cert.TLSConfig(), CanServeHost: n.cert.CanServe,
		BaseDomain: c.BaseDomain, ControlSNI: c.ControlSNI, ReservedNames: c.ReservedNames,
		Tokens: n.accounts, AgentCA: ca.Certificate(), TrustedProxies: c.TrustedPrefixes(),
		TCPPortMin: rules.PortMin, TCPPortMax: rules.PortMax, Cluster: n.link, Version: n.version, Logger: logger,
	}
	if c.Public.HTTP > 0 {
		cfg.HTTPAddr = ":" + strconv.Itoa(c.Relay.HTTP)
	}
	if c.Public.Gateway > 0 {
		keyPEM, err := common.ReadClusterSecret("gateway-host-key")
		if err != nil {
			return relay.Config{}, err
		}
		signer, err := ssh.ParsePrivateKey(keyPEM)
		if err != nil {
			return relay.Config{}, fmt.Errorf("gateway-host-key: %w", err)
		}
		cfg.SSHGateway = &relay.GatewayConfig{Listen: ":" + strconv.Itoa(c.Relay.Gateway), HostKey: signer, Keys: n.accounts}
	}
	return cfg, nil
}

func (n *Node) loop(ctx context.Context) {
	beat := time.NewTicker(heartbeatInterval)
	resync := time.NewTicker(resyncInterval)
	defer beat.Stop()
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-beat.C:
			n.heartbeat()
		case <-resync.C:
			n.refresh()
			n.reloadCert()
		}
	}
}

func (n *Node) refresh() {
	if err := n.accounts.refresh(); err != nil {
		n.vnic.Resources().Logger().Warning("refresh credentials: ", err.Error())
	}
}

// refreshSoon coalesces bursts of pushed changes into one reload.
func (n *Node) refreshSoon() {
	if n.refreshPending.CompareAndSwap(false, true) {
		time.AfterFunc(time.Second, func() {
			n.refreshPending.Store(false)
			n.refresh()
		})
	}
}

func (n *Node) reloadCert() {
	if err := n.loadCert(); err != nil {
		n.vnic.Resources().Logger().Warning("tunnel certificate: ", err.Error())
	}
}

// relayRecord is this relay's TunRelay report.
func (n *Node) relayRecord(st relay.Status) *tun.TunRelay {
	c := common.Cluster()
	r := &tun.TunRelay{RelayId: n.relayID, PodIp: n.podIP, TlsPort: int32(c.Relay.TLS), HttpPort: int32(c.Relay.HTTP),
		StreamPort: int32(c.Relay.Stream), GatewayPort: int32(c.Relay.Gateway), OpsPort: int32(c.Relay.Ops),
		State: tun.TunRelayState_TUN_RELAY_STATE_READY, Sessions: int32(len(st.Sessions)), Version: n.version,
		StartedAt: n.startedAt.Unix(), CertNotAfter: n.cert.NotAfter().Unix()}
	if n.srv.Draining() {
		r.State = tun.TunRelayState_TUN_RELAY_STATE_DRAINING
	}
	for _, s := range st.Sessions {
		for _, t := range s.Tunnels {
			r.Tunnels++
			r.BytesIn += t.BytesIn
			r.BytesOut += t.BytesOut
		}
	}
	return r
}

// state is the relay's tunnels and agents as the registry records them.
func (n *Node) state(st relay.Status) ([]*tun.TunLiveTunnel, []*tun.TunAgent) {
	var tunnels []*tun.TunLiveTunnel
	var agents []*tun.TunAgent
	for _, s := range st.Sessions {
		a := &tun.TunAgent{AgentId: s.AgentID, TokenId: s.TokenID, TokenName: s.Token, SessionId: s.ID, Version: s.Version,
			Os: s.OS, Arch: s.Arch, PublicIp: hostOf(s.Remote), State: tun.TunAgentState_TUN_AGENT_STATE_ONLINE,
			ConnectedAt: s.ConnectedAt.Unix(), LastHeartbeat: s.LastSeen.Unix(), RttUs: s.RTTMicros, TunnelCount: int32(len(s.Tunnels))}
		for _, t := range s.Tunnels {
			typ, _ := common.TunnelTypeOf(t.Type)
			tunnels = append(tunnels, &tun.TunLiveTunnel{TunnelId: t.TunnelID, Name: t.Name, Type: typ, Hostname: t.Hostname,
				Domains: t.Domains, PublicPort: int32(t.PublicPort), AgentId: s.AgentID, TokenId: s.TokenID, SessionId: s.ID,
				State: tun.TunLiveState_TUN_LIVE_STATE_ACTIVE, ConnectedAt: s.ConnectedAt.Unix(), AccessToken: t.AccessToken,
				ActiveConns: t.ActiveConns, TotalConns: t.TotalConns, BytesIn: t.BytesIn, BytesOut: t.BytesOut})
			a.ActiveStreams += t.ActiveConns
			a.BytesIn += t.BytesIn
			a.BytesOut += t.BytesOut
		}
		agents = append(agents, a)
	}
	return tunnels, agents
}

func (n *Node) heartbeat() {
	st := n.srv.Status()
	tunnels, agents := n.state(st)
	n.link.tell(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_HEARTBEAT, Relay: n.relayRecord(st),
		Tunnels: tunnels, Agents: agents})
}

// announce reports the relay's full state; tunnels now held elsewhere are
// closed.
func (n *Node) announce() {
	st := n.srv.Status()
	tunnels, agents := n.state(st)
	resp, err := n.link.ask(&tun.TunClaimRequest{Kind: tun.TunClaimKind_TUN_CLAIM_KIND_ANNOUNCE, Relay: n.relayRecord(st),
		Tunnels: tunnels, Agents: agents})
	if err != nil {
		n.vnic.Resources().Logger().Warning("announce: ", err.Error())
		return
	}
	for _, name := range resp.Conflicts {
		for _, t := range tunnels {
			if t.Name == name {
				n.srv.CloseTunnel(t.TunnelId, relay.ReasonTakeover)
			}
		}
	}
}

func hostOf(addr string) string {
	if h, _, err := net.SplitHostPort(addr); err == nil {
		return h
	}
	return addr
}

// opsHandler answers /healthz before the relay exists, then hands every
// request to the relay's own ops handler.
type opsHandler struct {
	h atomic.Pointer[http.Handler]
}

func (o *opsHandler) set(h http.Handler) { o.h.Store(&h) }

func (o *opsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h := o.h.Load(); h != nil {
		(*h).ServeHTTP(w, r)
		return
	}
	if r.URL.Path == "/healthz" {
		fmt.Fprintln(w, "starting")
		return
	}
	http.Error(w, "starting", http.StatusServiceUnavailable)
}
