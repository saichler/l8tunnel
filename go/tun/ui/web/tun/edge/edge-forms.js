// The edge domain form: general settings, the certificate, and the port
// forwarding table. The TUNNEL_BASE row's names and forwards follow
// cluster.yaml, so tun-actions.js opens it with tunnelBaseForm().
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const ro = TunForms.readOnly;
    const e = TunEdge.enums;

    // One port forward: the protocol, the incoming port and the port it
    // forwards to. A new forward gets the rest from the backend (an ID,
    // passthrough, this node as the target, enabled); the other settings
    // stay hidden, and the row editors keep them on existing forwards.
    const hidden = (key) => ({ key: key, hidden: true });
    const forwardColumns = [
        { key: 'protocol', label: 'Protocol', type: 'select', options: e.FORWARD_PROTOCOL, required: true },
        { key: 'listenPort', label: 'In port', type: 'number', required: true },
        { key: 'targetPort', label: 'To port', type: 'number', required: true },
        ...['forwardId', 'listenPortEnd', 'mode', 'targetKind', 'targets', 'targetDns', 'lb', 'backendScheme',
            'skipVerify', 'proxyProtocol', 'healthType', 'healthPath', 'healthInterval', 'enabled', 'note'].map(hidden)
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
