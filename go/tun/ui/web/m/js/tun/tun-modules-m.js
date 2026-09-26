// Mobile module data: the desktop enums, columns and forms of each
// sub-module (loaded by m/app.html), with the columns marked for cards --
// the title (primary), the subtitle (secondary), and the body fields; a
// hidden column stays out of the card.
(function() {
    'use strict';

    // cards decorates a model's desktop columns: primary is the title key,
    // secondary the subtitle keys, hidden the keys left off the card.
    function cards(columns, primary, secondary, hidden) {
        return columns.map(c => {
            const mc = Object.assign({}, c);
            if (mc.key === primary) mc.primary = true;
            else if ((secondary || []).indexOf(mc.key) !== -1) mc.secondary = true;
            else if ((hidden || []).indexOf(mc.key) !== -1) mc.hidden = true;
            return mc;
        });
    }

    // mobile builds a mobile namespace from a desktop one; layout maps each
    // model to [primary, secondary, hidden].
    function mobile(desktop, layout) {
        const columns = {};
        Object.keys(layout).forEach(model => {
            const l = layout[model];
            columns[model] = cards(desktop.columns[model], l[0], l[1], l[2]);
        });
        return { enums: desktop.enums, render: desktop.render, columns: columns, forms: desktop.forms, primaryKeys: desktop.primaryKeys };
    }

    window.MobileTunLive = mobile(TunLive, {
        TunAgent: ['agentId', ['state', 'tokenName'], ['publicIp', 'rttUs']],
        TunLiveTunnel: ['name', ['state', 'type'], ['bytesIn']],
        TunRelay: ['relayId', ['state', 'version'], ['podIp', 'bytesIn']],
        EdgeNode: ['edgeId', ['nodeIp', 'version'], ['totalConns']]
    });
    window.MobileTunAccess = mobile(TunAccess, {
        TunToken: ['name', ['description'], ['createdBy']],
        TunReservation: ['name', ['publicPort'], ['note']],
        TunGatewayKey: ['name', ['fingerprint'], []],
        TunAgentCert: ['commonName', ['revoked', 'certId'], []]
    });
    window.MobileTunEdge = mobile(TunEdge, {
        EdgeDomain: ['domain', ['kind', 'certStatus'], ['aliases']]
    });
    window.MobileTunAlerts = mobile(TunAlerts, {
        TunAlertRule: ['name', ['condition', 'enabled'], []]
    });

    // l8notify's own columns already carry their primary/secondary marks.
    MobileTunAlerts.columns.NotifyRecord = TunAlerts.columns.NotifyRecord;
    MobileTunAlerts.columns.IntegrationConfig = TunAlerts.columns.IntegrationConfig;

    Layer8MModuleRegistry.create('MobileTun', {
        'Tunnels': MobileTunLive,
        'Access': MobileTunAccess,
        'Edge': MobileTunEdge,
        'Alerts': MobileTunAlerts
    });
})();
