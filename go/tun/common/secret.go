package common

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ReadClusterSecret reads a file of the l8tunnel-cluster Secret.
func ReadClusterSecret(name string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(Cluster().SecretDir, name))
	if err != nil {
		return nil, fmt.Errorf("cluster secret %s: %w", name, err)
	}
	return data, nil
}

// ForwardKey is the key that signs the PROXY headers between the edge and
// the relays (the Secret stores it as hex).
func ForwardKey() ([]byte, error) {
	data, err := ReadClusterSecret("forward-key")
	if err != nil {
		return nil, err
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) < 32 {
		return nil, fmt.Errorf("cluster secret forward-key must be at least 32 bytes of hex")
	}
	return key, nil
}
