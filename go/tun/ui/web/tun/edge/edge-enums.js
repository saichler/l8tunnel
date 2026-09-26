// Enums and renderers of the edge (EdgeDomain and its port forwards).
// Values match proto/tun.proto.
(function() {
    'use strict';

    window.TunEdge = window.TunEdge || {};
    const factory = Layer8EnumFactory;
    const { createStatusRenderer, renderEnum } = Layer8DRenderers;

    const DOMAIN_KIND = factory.withValues([['Unspecified', null], ['Site', 'site'], ['Tunnel base', 'tunnel']]);
    const CERT_STATUS = factory.create([
        ['Unspecified', null, ''],
        ['Valid', 'valid', 'layer8d-status-active'],
        ['Expiring', 'expiring', 'layer8d-status-warning'],
        ['Expired', 'expired', 'layer8d-status-terminated'],
        ['Mismatch', 'mismatch', 'layer8d-status-terminated'],
        ['Missing', 'missing', 'layer8d-status-inactive']
    ]);
    const PROTOCOL = factory.withValues([['Unspecified', null], ['TLS', 'tls'], ['HTTP', 'http'], ['TCP', 'tcp']]);
    const MODE = factory.withValues([['Unspecified', null], ['Terminate', 'terminate'], ['Passthrough', 'passthrough'], ['Relay', 'relay']]);
    const TARGET_KIND = factory.withValues([['Unspecified', null], ['Targets', 'targets'], ['DNS name', 'dns'], ['Node local', 'local'], ['Relays', 'relays']]);
    const BACKEND_SCHEME = factory.withValues([['Unspecified', null], ['HTTPS', 'https'], ['HTTP', 'http']]);
    const LB = factory.withValues([['Unspecified', null], ['Round robin', 'roundrobin'], ['Least connections', 'leastconn'], ['Source hash', 'sourcehash'], ['Random', 'random']]);
    const HEALTH = factory.withValues([['Unspecified', null], ['None', 'none'], ['TCP', 'tcp'], ['HTTP', 'http'], ['HTTPS', 'https']]);

    TunEdge.enums = {
        DOMAIN_KIND: DOMAIN_KIND.enum, DOMAIN_KIND_VALUES: DOMAIN_KIND.values,
        // New domains are sites; the tunnel base is built in.
        SITE_KIND: { 1: 'Site' },
        CERT_STATUS: CERT_STATUS.enum, CERT_STATUS_VALUES: CERT_STATUS.values, CERT_STATUS_CLASSES: CERT_STATUS.classes,
        PROTOCOL: PROTOCOL.enum, MODE: MODE.enum, TARGET_KIND: TARGET_KIND.enum,
        // The protocol list of a port forward row: an HTTPS port is TLS,
        // passed through to the target.
        FORWARD_PROTOCOL: { 1: 'HTTPS', 2: 'HTTP', 3: 'TCP' },
        BACKEND_SCHEME: BACKEND_SCHEME.enum, LB: LB.enum, HEALTH: HEALTH.enum
    };

    const certStatus = createStatusRenderer(CERT_STATUS.enum, CERT_STATUS.classes);
    TunEdge.render = {
        domainKind: (v) => renderEnum(v, DOMAIN_KIND.enum),
        certStatus: certStatus,
        protocol: (v) => renderEnum(v, PROTOCOL.enum),
        // The certificate status badge with the days left to expiry.
        certBadge: (item) => {
            const badge = certStatus(item.certStatus);
            const notAfter = Number(item.certNotAfter || 0);
            if (!notAfter) return badge;
            const days = Math.floor((notAfter * 1000 - Date.now()) / 86400000);
            return badge + ' <span class="tun-muted">' + (days >= 0 ? days + ' days' : 'expired') + '</span>';
        }
    };
})();
