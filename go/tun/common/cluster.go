package common

import (
	"os"
	"sync"

	"github.com/saichler/l8tunnel/go/tunnel/config"
)

var (
	clusterMu sync.RWMutex
	cluster   *config.ClusterFile
)

// SetCluster installs the cluster configuration. Each process loads
// cluster.yaml once at startup (main) and sets it before activating
// services.
func SetCluster(f *config.ClusterFile) {
	clusterMu.Lock()
	defer clusterMu.Unlock()
	cluster = f
}

// Cluster returns the cluster configuration. It panics when none was set,
// which is a startup bug (fail fast).
func Cluster() *config.ClusterFile {
	clusterMu.RLock()
	defer clusterMu.RUnlock()
	if cluster == nil {
		panic("common.Cluster: SetCluster wasn't called at startup")
	}
	return cluster
}

// AllowSimulated reports whether this process accepts simulated records.
func AllowSimulated() bool {
	return os.Getenv(AllowSimulatedEnv) == "true"
}
