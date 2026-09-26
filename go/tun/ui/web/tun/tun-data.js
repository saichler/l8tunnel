// Reads whole l8tunnel tables for the views that aggregate them (the
// dashboard, the router ports, the version and applied-config badges).
(function() {
    'use strict';

    // list returns every row of a table. L8QL computes aggregates and
    // totals only on page 0, so the query asks for page 0 with a limit
    // 1000 (the most a query may ask for).
    async function list(endpoint, model, where) {
        const text = 'select * from ' + model + (where ? ' where ' + where : '') + ' limit 1000 page 0';
        const resp = await fetch(Layer8DConfig.resolveEndpoint(endpoint) + '?body=' +
            encodeURIComponent(JSON.stringify({ text: text })), { method: 'GET', headers: getAuthHeaders() });
        if (!resp.ok) throw new Error(model + ': HTTP ' + resp.status);
        const data = await resp.json();
        return data.list || [];
    }

    // liveEdges are the real edges that reported in the last two minutes
    // (an edge reports every 5 s).
    function liveEdges(nodes) {
        const since = Date.now() / 1000 - 120;
        return nodes.filter(n => !n.simulated && Number(n.lastSeen || 0) >= since);
    }

    window.TunData = { list: list, liveEdges: liveEdges };
})();
