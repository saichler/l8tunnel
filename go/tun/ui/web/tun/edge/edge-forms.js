// The edge domain form: general settings, the certificate, and the port
// forwarding table. The TUNNEL_BASE row's names and forwards follow
// cluster.yaml, so tun-actions.js opens it with tunnelBaseForm().
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const ro = TunForms.readOnly;
    const e = TunEdge.enums;

    // One port forward. Targets are "host:port" or "host:port*weight"; a
    // leading "!" disables one.
    const forwardColumns = [
        { key: 'forwardId', label: 'ID', type: 'text' },
        { key: 'listenPort', label: 'Port', type: 'number', required: true },
        { key: 'listenPortEnd', label: 'To (range)', type: 'number' },
        { key: 'protocol', label: 'Protocol', type: 'select', options: e.PROTOCOL, required: true },
        { key: 'mode', label: 'Mode', type: 'select', options: e.MODE, required: true },
        { key: 'targetKind', label: 'Target', type: 'select', options: e.TARGET_KIND, required: true },
        { key: 'targets', label: 'Members', type: 'tags' },
        { key: 'targetDns', label: 'DNS name', type: 'text' },
        { key: 'targetPort', label: 'Target port', type: 'number' },
        { key: 'lb', label: 'Balancing', type: 'select', options: e.LB },
        { key: 'backendScheme', label: 'Backend', type: 'select', options: e.BACKEND_SCHEME },
        { key: 'skipVerify', label: 'Skip verify (insecure)', type: 'checkbox' },
        { key: 'proxyProtocol', label: 'PROXY v2', type: 'checkbox' },
        { key: 'healthType', label: 'Health', type: 'select', options: e.HEALTH },
        { key: 'healthPath', label: 'Health path', type: 'text' },
        { key: 'healthInterval', label: 'Every (s)', type: 'number' },
        { key: 'enabled', label: 'Enabled', type: 'checkbox' },
        { key: 'note', label: 'Note', type: 'text' }
    ];

    const certificateSection = () => f.section('Certificate', [
        ...f.file('certStoragePath', 'Certificate chain (PEM)'),
        ...f.file('keyStoragePath', 'Private key (PEM)'),
        ...ro([
            ...f.select('certStatus', 'Status', e.CERT_STATUS),
            ...f.text('certSubject', 'Subject'),
            ...f.tags('certSans', 'Names'),
            ...f.text('certIssuer', 'Issuer'),
            ...f.date('certNotAfter', 'Expires'),
            ...f.text('certFingerprint', 'Fingerprint')
        ])
    ]);

    const settings = () => [
        ...f.checkbox('enabled', 'Enabled'),
        ...f.tags('allowIps', 'Allow IPs (CIDRs, empty allows all)'),
        ...f.tags('denyIps', 'Deny IPs (CIDRs)'),
        ...f.textarea('note', 'Note'),
        ...ro([...f.number('configVersion', 'Config version')])
    ];

    TunEdge.forms = {
        EdgeDomain: f.form('Domain', [
            f.section('General', [
                ...f.text('domain', 'Domain', true),
                ...f.tags('aliases', 'Aliases'),
                ...f.select('kind', 'Kind', e.SITE_KIND, true),
                ...settings()
            ]),
            certificateSection(),
            f.section('Port forwarding', [...f.inlineTable('portForwards', 'Port forwards', forwardColumns)])
        ])
    };

    // editForm is the form for an existing site: its kind can't change.
    TunEdge.editForm = f.form('Domain', [
        f.section('General', [
            ...f.text('domain', 'Domain', true),
            ...f.tags('aliases', 'Aliases'),
            ...ro([...f.select('kind', 'Kind', e.DOMAIN_KIND)]),
            ...settings()
        ]),
        certificateSection(),
        f.section('Port forwarding', [...f.inlineTable('portForwards', 'Port forwards', forwardColumns)])
    ]);

    // tunnelBaseForm is the TUNNEL_BASE row's form: its names and forwards
    // come from cluster.yaml (the backend resets them), so only the
    // certificate and the settings can change.
    TunEdge.tunnelBaseForm = f.form('Tunnel base domain', [
        f.section('General', [
            ...ro([
                ...f.text('domain', 'Domain'),
                ...f.tags('aliases', 'Aliases'),
                ...f.select('kind', 'Kind', e.DOMAIN_KIND)
            ]),
            ...settings()
        ]),
        certificateSection(),
        f.section('Port forwarding (from cluster.yaml)', ro([...f.inlineTable('portForwards', 'Port forwards', forwardColumns)]))
    ]);
})();
