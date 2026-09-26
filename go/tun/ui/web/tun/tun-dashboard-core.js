// The dashboard numbers, shared by both shells: loaded from the live and
// edge tables and computed the same way on desktop and mobile.
(function() {
    'use strict';

    function compute(relays, agents, tunnels, nodes, domains) {
        const real = (xs) => xs.filter(x => !x.simulated);
        const day = Date.now() / 1000 - 86400;
        const byType = {};
        real(tunnels).forEach(t => {
            const label = TunLive.enums.TUNNEL_TYPE[t.type] || 'Other';
            byType[label] = (byType[label] || 0) + 1;
        });
        let unhealthy = 0;
        TunData.liveEdges(nodes).forEach(n => (n.backends || []).forEach(b => { if (!b.healthy) unhealthy++; }));
        const expiries = domains.map(d => Number(d.certNotAfter || 0)).filter(Boolean);
        const soonest = expiries.length ? Math.min(...expiries) : 0;
        return {
            readyRelays: real(relays).filter(r => Number(r.state) === 1).length,
            relays: real(relays).length,
            online: real(agents).filter(a => Number(a.state) === 1).length,
            offline24h: real(agents).filter(a => Number(a.state) !== 1 && Number(a.lastSeen || 0) >= day).length,
            tunnels: real(tunnels).length,
            byType: byType,
            unhealthy: unhealthy,
            certDays: soonest ? Math.floor((soonest * 1000 - Date.now()) / 86400000) : null
        };
    }

    window.TunDashboardCore = {
        // load reads the tables and returns the KPIs.
        load: async function() {
            const [relays, agents, tunnels, nodes, domains] = await Promise.all([
                TunData.list('/42/TunRelay', 'TunRelay'), TunData.list('/42/TunAgent', 'TunAgent'),
                TunData.list('/42/TunLive', 'TunLiveTunnel'), TunData.list('/41/EdgeNode', 'EdgeNode'),
                TunData.list('/41/EdgeDomain', 'EdgeDomain')
            ]);
            return compute(relays, agents, tunnels, nodes, domains);
        },
        compute: compute,
        // typesText is the tunnels-by-type breakdown, e.g. "HTTP 2 · SSH 1".
        typesText: (k) => Object.keys(k.byType).sort().map(t => t + ' ' + k.byType[t]).join(' · ') || 'none',
        // The live tables whose changes refresh the dashboard.
        LIVE_MODELS: ['TunRelay', 'TunAgent', 'TunLiveTunnel']
    };
})();
