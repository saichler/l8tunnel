package mocks

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"

	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/types/l8api"
)

// Phase 4: edge sites. Each gets a self-signed certificate for its names,
// uploaded through FileStore (one expires in ten days, for the status
// badge; the backend refuses an already expired one), and port forwards in
// every protocol, mode, target kind and balancing algorithm. Their TCP
// ports are unique (a TCP port can't be shared); TLS and HTTP ports are
// shared by name.
func generateEdgeDomains(c *Client, s *MockDataStore, tag string) error {
	e := struct {
		tls, http, tcp tun.EdgeProtocol
	}{tun.EdgeProtocol_EDGE_PROTOCOL_TLS, tun.EdgeProtocol_EDGE_PROTOCOL_HTTP, tun.EdgeProtocol_EDGE_PROTOCOL_TCP}
	lbs := []tun.EdgeLbAlgorithm{tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_ROUND_ROBIN, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_LEAST_CONN,
		tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_SOURCE_HASH, tun.EdgeLbAlgorithm_EDGE_LB_ALGORITHM_RANDOM}
	for i, site := range siteNames {
		domain := fmt.Sprintf("demo-%s%s.invalid", site, tag)
		d := &tun.EdgeDomain{Domain: domain, Aliases: []string{"www." + domain}, Kind: tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE,
			Enabled: i != 7, Note: "Mock site " + site}
		if i%3 == 1 {
			d.AllowIps = []string{"192.168.0.0/16", "10.0.0.0/8"}
		}
		hasCert := i != 6 // one site without a certificate: passthrough only
		if hasCert {
			days := 365
			if i == 2 {
				days = 10 // expiring soon
			}
			certPath, keyPath, err := uploadCert(c, domain, days)
			if err != nil {
				return err
			}
			d.CertStoragePath, d.KeyStoragePath = certPath, keyPath
		}
		members := targets(i)
		port := 41000 + s.portOffset*100 + int32(i*10)
		lb := lbs[i%len(lbs)]
		if hasCert {
			d.PortForwards = append(d.PortForwards, &tun.EdgePortForward{ForwardId: "https", ListenPort: 443, Protocol: e.tls,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_TERMINATE, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
				Targets: members, Lb: lb, BackendScheme: tun.EdgeBackendScheme_EDGE_BACKEND_SCHEME_HTTP,
				HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_HTTP, HealthPath: "/healthz", HealthInterval: 15, Enabled: true})
		} else {
			d.PortForwards = append(d.PortForwards, &tun.EdgePortForward{ForwardId: "tls", ListenPort: 443, Protocol: e.tls,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS,
				Targets: members, Lb: lb, HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_TCP, Enabled: true})
		}
		d.PortForwards = append(d.PortForwards,
			&tun.EdgePortForward{ForwardId: "http", ListenPort: 80, Protocol: e.http,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_DNS,
				TargetDns: "backend-" + site + ".example.test", TargetPort: 8080, HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_NONE, Enabled: true},
			&tun.EdgePortForward{ForwardId: "tcp", ListenPort: port, Protocol: e.tcp,
				Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH, TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_NODE_LOCAL,
				TargetPort: 5432, ProxyProtocol: i%2 == 0, HealthType: tun.EdgeHealthType_EDGE_HEALTH_TYPE_TCP, Enabled: i%4 != 3,
				Note: "Database"})
		if i%2 == 1 {
			d.PortForwards = append(d.PortForwards, &tun.EdgePortForward{ForwardId: "range", ListenPort: port + 1, ListenPortEnd: port + 4,
				Protocol: e.tcp, Mode: tun.EdgeForwardMode_EDGE_FORWARD_MODE_PASSTHROUGH,
				TargetKind: tun.EdgeTargetKind_EDGE_TARGET_KIND_TARGETS, Targets: members, Lb: lb, Enabled: true})
		}
		if err := post(c, common.AreaEdge, common.DomainService, d, nil); err != nil {
			return err
		}
		s.TunDomainIDs = append(s.TunDomainIDs, domain)
	}
	return nil
}

// targets is a weighted pool of 1-4 members; some are disabled ("!").
func targets(i int) []string {
	n := 1 + i%4
	out := make([]string, 0, n)
	for m := 0; m < n; m++ {
		t := fmt.Sprintf("10.20.%d.%d:8080", i, 10+m)
		if m == 1 {
			t += "*2"
		}
		if m == 3 {
			t = "!" + t
		}
		out = append(out, t)
	}
	return out
}

// uploadCert creates a self-signed certificate for domain and www.domain,
// valid for days, and uploads the chain and the key through FileStore.
func uploadCert(c *Client, domain string, days int) (certPath, keyPath string, err error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: domain},
		DNSNames: []string{domain, "www." + domain}, NotBefore: time.Now().Add(-time.Hour),
		NotAfter: time.Now().AddDate(0, 0, days), KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		return "", "", err
	}
	keyDER, err := x509.MarshalECPrivateKey(key)
	if err != nil {
		return "", "", err
	}
	certPath, err = upload(c, domain+".crt", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	if err != nil {
		return "", "", err
	}
	keyPath, err = upload(c, domain+".key", pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}))
	return certPath, keyPath, err
}

func upload(c *Client, name string, data []byte) (string, error) {
	resp := &l8api.L8FileUploadResponse{}
	if err := post(c, common.FileStoreArea, common.FileStoreService, &l8api.L8FileUploadRequest{
		FileName: name, MimeType: "application/x-pem-file", FileData: data, DocumentId: common.CertDocumentID, Version: 1,
	}, resp); err != nil {
		return "", err
	}
	return resp.StoragePath, nil
}
