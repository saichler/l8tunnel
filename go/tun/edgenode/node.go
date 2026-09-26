package edgenode

import (
	"context"
	"fmt"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync/atomic"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tun/edge/domains"
	"github.com/saichler/l8tunnel/go/tunnel/admin"
	"github.com/saichler/l8tunnel/go/tunnel/certs"
	"github.com/saichler/l8tunnel/go/tunnel/edge"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"google.golang.org/protobuf/encoding/protojson"
)

const (
	reportInterval = 5 * time.Second
	resyncInterval = time.Minute
	liveTTL        = 2 * time.Second
	cacheDir       = "/data/edge-cache"
)

// Node is the edge running in the cluster.
type Node struct {
	vnic      ifs.IVNic
	id        string
	nodeIP    string
	version   string
	edge      *edge.Edge
	certs     *certs.Set
	certFP    map[string]string // domain ID -> certificate fingerprint loaded
	live      *common.LiveView
	startedAt time.Time
	log       *slog.Logger

	reloadPending atomic.Bool
	reported      atomic.Bool // the EdgeNode record exists
}

// Run starts the edge and blocks until ctx ends.
func Run(ctx context.Context, vnic ifs.IVNic, version string, logger *slog.Logger) error {
	c := common.Cluster()
	n := &Node{vnic: vnic, id: os.Getenv("NODE_NAME"), nodeIP: os.Getenv("NODE_IP"), version: version,
		certs: certs.NewSet(), certFP: map[string]string{}, startedAt: time.Now(), log: logger}
	if n.id == "" {
		n.id, _ = os.Hostname()
	}
	key, err := common.ForwardKey()
	if err != nil {
		return err
	}
	n.live = common.NewLiveView(vnic, liveTTL)
	if n.edge, err = edge.New(edge.Config{BaseDomain: c.BaseDomain, ControlSNI: c.ControlSNI, NodeIP: n.nodeIP,
		ForwardKey: key, Live: &live{view: n.live}, Certs: n.certs, Logger: logger}); err != nil {
		return err
	}
	// The tunnel base's ports first, so tunnels work before (or without)
	// the management plane; the ops endpoints too, so liveness probes pass
	// while the domains load.
	n.edge.Apply([]*tun.EdgeDomain{bootstrapBase()}, 0)
	opsLn, err := net.Listen("tcp", ":"+strconv.Itoa(c.Edge.Ops))
	if err != nil {
		return fmt.Errorf("ops listener: %w", err)
	}
	go admin.Serve(ctx, opsLn, n.edge.OpsHandler(), logger)
	n.activateCtl()
	n.reload()
	go n.loop(ctx)
	<-ctx.Done()
	n.edge.Close()
	return nil
}

// bootstrapBase is the tunnel base domain as cluster.yaml defines it.
func bootstrapBase() *tun.EdgeDomain {
	base := common.Cluster().BaseDomain
	return &tun.EdgeDomain{DomainId: "bootstrap", Domain: base, Aliases: []string{"*." + base},
		Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE, Enabled: true, PortForwards: domains.TunnelBaseForwards()}
}

func (n *Node) loop(ctx context.Context) {
	report := time.NewTicker(reportInterval)
	resync := time.NewTicker(resyncInterval)
	defer report.Stop()
	defer resync.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-report.C:
			n.report()
		case <-resync.C:
			n.reload()
		}
	}
}

// reloadSoon coalesces bursts of pushed domain changes.
func (n *Node) reloadSoon() {
	if n.reloadPending.CompareAndSwap(false, true) {
		time.AfterFunc(500*time.Millisecond, func() {
			n.reloadPending.Store(false)
			n.reload()
		})
	}
}

// reload applies the stored domains, or the cache when the backend is
// unreachable.
func (n *Node) reload() {
	all, err := domains.Domains(n.vnic)
	if err != nil {
		cached, cerr := n.loadCache()
		if cerr != nil {
			n.log.Warn("edge domains unavailable and no cache", "error", err)
			return
		}
		n.log.Warn("management backend unreachable; using the cached edge domains", "error", err)
		all = cached
	} else {
		n.loadCerts(all)
		n.saveCache(all)
	}
	var version int64
	for _, d := range all {
		if d.ConfigVersion > version {
			version = d.ConfigVersion
		}
	}
	n.edge.Apply(all, version)
}

// loadCerts loads the certificates of TERMINATE sites that changed.
func (n *Node) loadCerts(all []*tun.EdgeDomain) {
	seen := map[string]bool{}
	for _, d := range all {
		if d.Kind != tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE || d.CertFingerprint == "" {
			continue
		}
		seen[d.DomainId] = true
		if n.certFP[d.DomainId] == d.CertFingerprint {
			continue
		}
		certPEM, err := common.FetchFile(d.CertStoragePath, n.vnic)
		if err == nil {
			var keyPEM []byte
			if keyPEM, err = common.FetchFile(d.KeyStoragePath, n.vnic); err == nil {
				if err = n.certs.Put(d.DomainId, certPEM, keyPEM, append([]string{d.Domain}, d.Aliases...)); err == nil {
					n.certFP[d.DomainId] = d.CertFingerprint
					n.writeCacheFile(d.DomainId+".crt", certPEM)
					n.writeCacheFile(d.DomainId+".key", keyPEM)
					continue
				}
			}
		}
		n.log.Warn("edge: certificate not loaded", "domain", d.Domain, "error", err)
	}
	for id := range n.certFP {
		if !seen[id] {
			n.certs.Remove(id)
			delete(n.certFP, id)
		}
	}
}

// report writes this edge's EdgeNode record.
func (n *Node) report() {
	st := n.edge.Status()
	rec := &tun.EdgeNode{EdgeId: n.id, NodeIp: n.nodeIP, Version: n.version, ConfigVersion: st.Version,
		Listeners: st.Listeners, Backends: st.Backends, TotalConns: st.Accepted, StartedAt: n.startedAt.Unix(),
		LastSeen: time.Now().Unix()}
	// POST creates the record once; each later report replaces it with PUT
	// (a report is the whole state: a PATCH would keep listeners, errors and
	// backends that are gone). A PUT that fails creates it again.
	if n.reported.Load() {
		if err := l8common.PutEntity(common.EdgeNodeService, common.AreaEdge, rec, n.vnic); err == nil {
			return
		}
	}
	if _, err := l8common.PostEntity(common.EdgeNodeService, common.AreaEdge, rec, n.vnic); err != nil {
		n.log.Debug("edge report failed", "error", err)
		return
	}
	n.reported.Store(true)
}

func (n *Node) saveCache(all []*tun.EdgeDomain) {
	data, err := protojson.Marshal(&tun.EdgeDomainList{List: all})
	if err == nil {
		n.writeCacheFile("domains.json", data)
	}
}

func (n *Node) loadCache() ([]*tun.EdgeDomain, error) {
	data, err := os.ReadFile(filepath.Join(cacheDir, "domains.json"))
	if err != nil {
		return nil, err
	}
	list := &tun.EdgeDomainList{}
	if err := protojson.Unmarshal(data, list); err != nil {
		return nil, err
	}
	for _, d := range list.List {
		certPEM, err1 := os.ReadFile(filepath.Join(cacheDir, d.DomainId+".crt"))
		keyPEM, err2 := os.ReadFile(filepath.Join(cacheDir, d.DomainId+".key"))
		if err1 == nil && err2 == nil && n.certs.Put(d.DomainId, certPEM, keyPEM, append([]string{d.Domain}, d.Aliases...)) == nil {
			n.certFP[d.DomainId] = d.CertFingerprint
		}
	}
	return list.List, nil
}

// writeCacheFile writes a cache file (certificate keys included) mode 0600.
func (n *Node) writeCacheFile(name string, data []byte) {
	if err := os.MkdirAll(cacheDir, 0o700); err != nil {
		return
	}
	tmp := filepath.Join(cacheDir, name+".tmp")
	if os.WriteFile(tmp, data, 0o600) == nil {
		os.Rename(tmp, filepath.Join(cacheDir, name))
	}
}
