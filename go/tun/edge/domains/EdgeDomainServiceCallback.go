package domains

import (
	"errors"
	"fmt"
	"strings"
	"time"

	l8common "github.com/saichler/l8common/go/common"
	"github.com/saichler/l8tunnel/go/tun/common"
	"github.com/saichler/l8tunnel/go/tunnel/edgeconf"
	"github.com/saichler/l8tunnel/go/types/tun"
	"github.com/saichler/l8types/go/ifs"
	"google.golang.org/protobuf/proto"
)

func newEdgeDomainServiceCallback() ifs.IServiceCallback {
	return common.NewCallback(common.Hooks{
		TypeName: "EdgeDomain",
		Check:    func(e interface{}) bool { _, ok := e.(*tun.EdgeDomain); return ok },
		SetID: func(e interface{}) {
			l8common.GenerateID(&e.(*tun.EdgeDomain).DomainId)
		},
		Validate: validate,
		Changed: func(e interface{}, action ifs.Action, vnic ifs.IVNic) {
			// Edges rebuild listeners and pools; relays reload the tunnel
			// certificate and the names that sites block.
			common.PushToEdges(e, action, vnic)
			common.PushToRelays(e, action, vnic)
		},
	})
}

func validate(e interface{}, action ifs.Action, vnic ifs.IVNic) (interface{}, error) {
	d := e.(*tun.EdgeDomain)
	all, err := Domains(vnic)
	if err != nil {
		return nil, err
	}
	var existing *tun.EdgeDomain
	for _, o := range all {
		if o.DomainId == d.DomainId {
			existing = o
		}
	}
	if action != ifs.POST && existing == nil {
		return nil, fmt.Errorf("edge domain %s doesn't exist", d.DomainId)
	}
	if action == ifs.PATCH {
		// Validate and store the whole domain as it will be after the
		// patch, so the checks see every port forward.
		d = mergePatch(existing, d)
	}
	if d.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_UNSPECIFIED {
		d.Kind = tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE
	}
	if err := protectTunnelBase(d, existing); err != nil {
		return nil, err
	}
	if err := edgeconf.NormalizeNames(d); err != nil {
		return nil, err
	}
	base := common.Cluster().BaseDomain
	if d.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_SITE {
		for _, n := range edgeconf.Names(d) {
			if strings.HasPrefix(n, "*.") && (n == "*."+base || strings.HasSuffix(n, "."+base)) {
				return nil, fmt.Errorf("%s would cover tunnel names; list the site names under %s one by one", n, base)
			}
		}
	}
	// The certificate first: terminate forwards need its status.
	if err := checkCertificate(d, existing, vnic); err != nil {
		return nil, err
	}
	if err := edgeconf.ValidateDomain(d, all, base); err != nil {
		return nil, err
	}
	d.ConfigVersion = time.Now().UnixNano()
	if action == ifs.PATCH {
		return d, nil
	}
	return nil, nil
}

// mergePatch applies the fields a patch sets to a copy of the stored domain.
func mergePatch(existing, patch *tun.EdgeDomain) *tun.EdgeDomain {
	m := proto.Clone(existing).(*tun.EdgeDomain)
	proto.Merge(m, patch)
	// Repeated fields are replaced, not appended, when the patch sets them.
	if patch.Aliases != nil {
		m.Aliases = patch.Aliases
	}
	if patch.AllowIps != nil {
		m.AllowIps = patch.AllowIps
	}
	if patch.DenyIps != nil {
		m.DenyIps = patch.DenyIps
	}
	if patch.PortForwards != nil {
		m.PortForwards = patch.PortForwards
	}
	return m
}

// protectTunnelBase keeps the TUNNEL_BASE row's identity and port forwards
// as cluster.yaml defines them, and stops a site from becoming one.
func protectTunnelBase(d, existing *tun.EdgeDomain) error {
	wasBase := existing != nil && existing.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE
	isBase := d.Kind == tun.EdgeDomainKind_EDGE_DOMAIN_KIND_TUNNEL_BASE
	switch {
	case existing != nil && wasBase != isBase:
		return errors.New("a domain's kind can't change")
	case !isBase:
		return nil
	}
	base := common.Cluster().BaseDomain
	d.Domain = base
	d.Aliases = []string{"*." + base}
	d.PortForwards = tunnelBaseForwards()
	return nil
}

// checkCertificate validates newly uploaded files and fills the summary
// fields; clients can't set the summary themselves.
func checkCertificate(d, existing *tun.EdgeDomain, vnic ifs.IVNic) error {
	unchanged := existing != nil && d.CertStoragePath == existing.CertStoragePath &&
		d.KeyStoragePath == existing.KeyStoragePath && existing.CertFingerprint != ""
	switch {
	case d.CertStoragePath == "" && d.KeyStoragePath == "":
		setSummary(d, nil)
		return nil
	case d.CertStoragePath == "" || d.KeyStoragePath == "":
		return errors.New("upload both the certificate chain and its private key")
	case unchanged:
		copySummary(d, existing)
		return nil
	}
	certPEM, err := common.FetchFile(d.CertStoragePath, vnic)
	if err != nil {
		return err
	}
	keyPEM, err := common.FetchFile(d.KeyStoragePath, vnic)
	if err != nil {
		return err
	}
	sum, err := edgeconf.SummarizeCert(certPEM, keyPEM, edgeconf.Names(d), time.Now())
	if err != nil {
		return err
	}
	switch sum.Status {
	case tun.EdgeCertStatus_EDGE_CERT_STATUS_MISMATCH, tun.EdgeCertStatus_EDGE_CERT_STATUS_EXPIRED:
		return errors.New(sum.Problem)
	}
	setSummary(d, &sum)
	return nil
}

func setSummary(d *tun.EdgeDomain, s *edgeconf.CertSummary) {
	if s == nil {
		d.CertSubject, d.CertSans, d.CertIssuer, d.CertNotAfter, d.CertFingerprint = "", nil, "", 0, ""
		d.CertStatus = tun.EdgeCertStatus_EDGE_CERT_STATUS_MISSING
		return
	}
	d.CertSubject, d.CertSans, d.CertIssuer = s.Subject, s.SANs, s.Issuer
	d.CertNotAfter, d.CertFingerprint, d.CertStatus = s.NotAfter.Unix(), s.Fingerprint, s.Status
}

func copySummary(d, from *tun.EdgeDomain) {
	d.CertSubject, d.CertSans, d.CertIssuer = from.CertSubject, from.CertSans, from.CertIssuer
	d.CertNotAfter, d.CertFingerprint, d.CertStatus = from.CertNotAfter, from.CertFingerprint, from.CertStatus
}
