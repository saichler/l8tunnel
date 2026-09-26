// Table columns of the access services.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;
    const esc = Layer8DUtils.escapeHtml;

    // policySummary is one line describing what a token allows.
    function policySummary(p) {
        if (!p) return 'any name';
        const parts = [];
        parts.push((p.names && p.names.length) ? 'names ' + p.names.join(', ') : 'any name');
        if (p.types && p.types.length) {
            parts.push(p.types.map(t => TunAccess.enums.TUNNEL_TYPE[t] || t).join('/'));
        }
        if (p.ports) parts.push('ports ' + p.ports);
        if (p.maxTunnels) parts.push('max ' + p.maxTunnels);
        if (p.requireCert) parts.push('certificate required');
        return parts.join('; ');
    }

    TunAccess.columns = {
        TunToken: [
            ...col.col('name', 'Name'),
            ...col.col('description', 'Description'),
            ...col.custom('policy', 'Policy', (item) => esc(policySummary(item.policy)), { sortKey: false }),
            ...col.custom('createdAt', 'Created', (item) => TunLive.render.when(item.createdAt)),
            ...col.col('createdBy', 'Created by')
        ],
        TunReservation: [
            ...col.col('name', 'Name'),
            ...col.col('tokenId', 'Token'),
            ...col.number('publicPort', 'Public port'),
            ...col.col('note', 'Note'),
            ...col.custom('createdAt', 'Created', (item) => TunLive.render.when(item.createdAt))
        ],
        TunGatewayKey: [
            ...col.col('name', 'Name'),
            ...col.col('fingerprint', 'Fingerprint'),
            ...col.custom('tunnels', 'Tunnels', (item) => Layer8DRenderers.renderTags(item.tunnels || []), { sortKey: false }),
            ...col.custom('createdAt', 'Created', (item) => TunLive.render.when(item.createdAt))
        ],
        TunAgentCert: [
            ...col.col('certId', 'Serial'),
            ...col.col('commonName', 'Common name'),
            ...col.col('tokenId', 'Token'),
            ...col.custom('revoked', 'Status', (item) => TunAccess.render.revoked(item.revoked)),
            ...col.custom('notAfter', 'Expires', (item) => TunLive.render.day(item.notAfter)),
            ...col.custom('createdAt', 'Issued', (item) => TunLive.render.when(item.createdAt))
        ]
    };

    TunAccess.primaryKeys = { TunToken: 'tokenId', TunReservation: 'reservationId', TunGatewayKey: 'keyId', TunAgentCert: 'certId' };
    TunAccess.policySummary = policySummary;
})();
