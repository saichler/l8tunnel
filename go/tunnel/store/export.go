package store

import (
	"encoding/json"
	"fmt"

	"github.com/saichler/l8tunnel/go/tunnel/auth"
)

// ExportVersion is the format version of Export.
const ExportVersion = 1

// Export is what "l8tunnel-server export" writes, for moving a standalone
// relay's state to the Kubernetes management plane. Token hashes and IDs
// are kept, so existing agent tokens keep working. The agent CA is exported
// separately, as PEM files for a Kubernetes Secret.
type Export struct {
	Version      int                 `json:"version"`
	Tokens       []*auth.TokenRecord `json:"tokens"`
	Reservations []*Reservation      `json:"reservations"`
	GatewayKeys  []*auth.GatewayKey  `json:"gateway_keys"`
}

// Export collects the tokens, reservations and gateway keys.
func (s *Store) Export() (*Export, error) {
	tokens, err := s.Tokens()
	if err != nil {
		return nil, err
	}
	reservations, err := s.Reservations()
	if err != nil {
		return nil, err
	}
	keys, err := s.GatewayKeys()
	if err != nil {
		return nil, err
	}
	return &Export{Version: ExportVersion, Tokens: tokens, Reservations: reservations, GatewayKeys: keys}, nil
}

// ParseExport reads an export and checks its version.
func ParseExport(data []byte) (*Export, error) {
	e := &Export{}
	if err := json.Unmarshal(data, e); err != nil {
		return nil, fmt.Errorf("parse the export: %w", err)
	}
	if e.Version != ExportVersion {
		return nil, fmt.Errorf("export version %d isn't supported (want %d)", e.Version, ExportVersion)
	}
	return e, nil
}
