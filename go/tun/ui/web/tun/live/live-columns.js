// Table columns of the live tables.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;
    const e = TunLive.enums;
    const r = TunLive.render;
    const esc = Layer8DUtils.escapeHtml;

    // Online agents show when they connected; the others when they were
    // last seen.
    const since = (item) => r.when(Number(item.state) === 1 ? item.connectedAt : item.lastSeen);

    TunLive.columns = {
        TunAgent: [
            ...col.status('state', 'State', e.AGENT_STATE_VALUES, r.agentState),
            ...col.col('agentId', 'Agent'),
            ...col.custom('tokenName', 'Token or certificate', (item) =>
                esc(item.certSerial ? 'cert ' + item.certSerial : (item.tokenName || item.tokenId || '-'))),
            ...col.custom('version', 'Version', (item) => TunLive.renderAgentVersion(item.version)),
            ...col.custom('os', 'OS', (item) => esc([item.os, item.arch].filter(Boolean).join('/') || '-')),
            ...col.col('publicIp', 'Public IP'),
            ...col.col('relayId', 'Relay'),
            ...col.enum('transport', 'Transport', e.TRANSPORT_VALUES, r.transport),
            ...col.custom('lastSeen', 'Connected / last seen', since),
            ...col.custom('rttUs', 'RTT', (item) => r.rtt(item.rttUs)),
            ...col.number('tunnelCount', 'Tunnels')
        ],
        TunLiveTunnel: [
            ...col.status('state', 'State', e.LIVE_STATE_VALUES, r.liveState),
            ...col.col('name', 'Name'),
            ...col.enum('type', 'Type', e.TUNNEL_TYPE_VALUES, r.tunnelType),
            ...col.custom('hostname', 'Endpoint', (item) =>
                esc(item.publicPort ? 'port ' + item.publicPort : (item.hostname || '-'))),
            ...col.custom('domains', 'Custom domains', (item) => Layer8DRenderers.renderTags(item.domains || [])),
            ...col.col('relayId', 'Relay'),
            ...col.col('agentId', 'Agent'),
            ...col.number('activeConns', 'Active'),
            ...col.custom('bytesIn', 'In / out', (item) => r.bytes(item.bytesIn) + ' / ' + r.bytes(item.bytesOut)),
            ...col.custom('connectedAt', 'Connected', (item) => TunLive.render.when(item.connectedAt))
        ],
        TunRelay: [
            ...col.status('state', 'State', e.RELAY_STATE_VALUES, r.relayState),
            ...col.col('relayId', 'Relay'),
            ...col.col('podIp', 'Pod IP'),
            ...col.col('version', 'Version'),
            ...col.number('sessions', 'Agents'),
            ...col.number('tunnels', 'Tunnels'),
            ...col.custom('bytesIn', 'In / out', (item) => r.bytes(item.bytesIn) + ' / ' + r.bytes(item.bytesOut)),
            ...col.custom('certNotAfter', 'Certificate expires', (item) => TunLive.render.day(item.certNotAfter)),
            ...col.custom('lastSeen', 'Last seen', (item) => TunLive.render.when(item.lastSeen))
        ],
        EdgeNode: [
            ...col.col('edgeId', 'Edge'),
            ...col.col('nodeIp', 'Node IP'),
            ...col.col('version', 'Version'),
            ...col.number('configVersion', 'Config version'),
            ...col.custom('listeners', 'Listeners bound', (item) => {
                const ls = item.listeners || [];
                return esc(ls.filter(l => l.bound).length + ' / ' + ls.length);
            }, { sortKey: false }),
            ...col.custom('backends', 'Backends healthy', (item) => {
                const bs = item.backends || [];
                return esc(bs.filter(b => b.healthy).length + ' / ' + bs.length);
            }, { sortKey: false }),
            ...col.number('activeConns', 'Active'),
            ...col.number('totalConns', 'Total'),
            ...col.custom('lastSeen', 'Last seen', (item) => TunLive.render.when(item.lastSeen))
        ]
    };

    TunLive.primaryKeys = { TunAgent: 'agentId', TunLiveTunnel: 'name', TunRelay: 'relayId', EdgeNode: 'edgeId' };

    // The newest relay version, loaded when the Tunnels section opens;
    // agents older than it are highlighted.
    TunLive.relayVersion = '';
    TunLive.renderAgentVersion = function(version) {
        const v = esc(version || '-');
        return version && TunLive.relayVersion && compareVersions(version, TunLive.relayVersion) < 0
            ? '<span class="layer8d-status layer8d-status-warning" title="older than the relays (' +
              esc(TunLive.relayVersion) + ')">' + v + '</span>'
            : v;
    };

    // compareVersions compares dotted numeric versions ("v1.4.2"); a
    // version that isn't numeric compares equal, so it's never flagged.
    function compareVersions(a, b) {
        const parse = (s) => String(s).replace(/^v/, '').split('.').map(Number);
        const x = parse(a), y = parse(b);
        if (x.some(isNaN) || y.some(isNaN)) return 0;
        for (let i = 0; i < Math.max(x.length, y.length); i++) {
            const d = (x[i] || 0) - (y[i] || 0);
            if (d) return d;
        }
        return 0;
    }
    TunLive.compareVersions = compareVersions;
})();
