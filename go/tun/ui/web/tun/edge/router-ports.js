// Edge > Router ports: every public port the edges listen on, one row per
// listener, from their reports. These are the ports to forward on the
// home router, and they show what's really bound, not only what's
// configured.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;
    const esc = Layer8DUtils.escapeHtml;
    const bound = (item) => item.bound
        ? '<span class="layer8d-status layer8d-status-active">Bound</span>'
        : '<span class="layer8d-status layer8d-status-terminated">' + esc(item.error || 'Not bound') + '</span>';

    const columns = [
        ...col.col('ports', 'Port'),
        ...col.custom('protocol', 'Protocol', (item) => TunEdge.render.protocol(item.protocol)),
        ...col.custom('domains', 'Domains', (item) => Layer8DRenderers.renderTags(item.domains || []), { sortKey: false }),
        ...col.custom('bound', 'State', bound),
        ...col.col('edgeId', 'Edge')
    ];

    async function render(containerId) {
        const container = document.getElementById(containerId);
        if (!container) return;
        let nodes;
        try {
            nodes = TunData.liveEdges(await TunData.list('/41/EdgeNode', 'EdgeNode'));
        } catch (e) {
            container.innerHTML = '<div class="tun-muted">Edge reports unavailable: ' + esc(e.message) + '</div>';
            return;
        }
        const rows = [];
        nodes.forEach(n => (n.listeners || []).forEach(l => rows.push({
            key: n.edgeId + ':' + l.port,
            ports: l.portEnd ? l.port + '-' + l.portEnd : String(l.port),
            protocol: l.protocol, domains: l.domains || [], bound: !!l.bound, error: l.error || '',
            edgeId: n.edgeId, sortPort: Number(l.port)
        })));
        rows.sort((a, b) => a.sortPort - b.sortPort || a.edgeId.localeCompare(b.edgeId));
        const table = new Layer8DTable({
            containerId: containerId, columns: columns, primaryKey: 'key', pageSize: 25,
            showActions: false, emptyMessage: 'No edge has reported in the last two minutes.'
        });
        table.init();
        table.setData(rows);
    }

    window.TunRouterPorts = { render: render };
})();
