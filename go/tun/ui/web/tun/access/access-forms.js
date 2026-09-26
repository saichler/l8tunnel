// Forms of the access services. Tokens and agent certificates are created
// through TunIssue (tun-issue.js), which shows the secret once; the forms
// here edit what can change afterwards.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const ro = TunForms.readOnly;

    // The policy fields, shared by the token form and the issue form.
    TunAccess.policyFields = function() {
        return [
            ...f.tags('policy.names', 'Tunnel names (patterns, empty allows any)'),
            ...f.multiselect('policy.types', 'Tunnel types (empty allows every type)', TunAccess.enums.TUNNEL_TYPE),
            ...f.number('policy.maxTunnels', 'Max tunnels (0 = no cap)'),
            ...f.text('policy.ports', 'Mode A ports (min-max, empty = the relay range)'),
            ...f.checkbox('policy.requireCert', 'Require an agent certificate'),
            ...f.tags('policy.domains', 'Custom domains (patterns, empty allows none)')
        ];
    };

    TunAccess.forms = {
        TunToken: f.form('Token', [
            f.section('Token', [
                ...f.text('name', 'Name', true),
                ...f.textarea('description', 'Description'),
                ...ro([
                    ...f.text('tokenId', 'Token ID'),
                    ...f.datetime('createdAt', 'Created'),
                    ...f.text('createdBy', 'Created by')
                ])
            ]),
            f.section('Policy', TunAccess.policyFields())
        ]),
        TunReservation: f.form('Reservation', [
            f.section('Reservation', [
                ...f.text('name', 'Tunnel name', true),
                ...f.reference('tokenId', 'Token', 'TunToken', true),
                ...f.number('publicPort', 'Public port (mode A, 0 = none)'),
                ...f.textarea('note', 'Note'),
                ...ro([...f.datetime('createdAt', 'Created')])
            ])
        ]),
        TunGatewayKey: f.form('Gateway key', [
            f.section('Key', [
                ...f.text('name', 'Name', true),
                ...f.textarea('publicKey', 'Public key (authorized_keys line)', true),
                ...f.tags('tunnels', 'Tunnels it may reach (name patterns)'),
                ...ro([
                    ...f.text('fingerprint', 'Fingerprint'),
                    ...f.datetime('createdAt', 'Created')
                ])
            ])
        ]),
        TunAgentCert: f.form('Agent certificate', [
            f.section('Certificate', ro([
                ...f.text('certId', 'Serial'),
                ...f.text('commonName', 'Common name'),
                ...f.text('tokenId', 'Token ID'),
                ...f.date('notBefore', 'Valid from'),
                ...f.date('notAfter', 'Expires'),
                ...f.text('fingerprint', 'Fingerprint'),
                ...f.checkbox('revoked', 'Revoked'),
                ...f.datetime('createdAt', 'Issued')
            ]))
        ])
    };
})();
