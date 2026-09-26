// Table columns of the edge domains.
(function() {
    'use strict';

    const col = Layer8ColumnFactory;
    const esc = Layer8DUtils.escapeHtml;

    // The lowest EdgeDomain version every live edge has applied, loaded
    // when the Edge section opens.
    TunEdge.appliedVersion = null;

    TunEdge.columns = {
        EdgeDomain: [
            ...col.col('domain', 'Domain'),
            ...col.custom('aliases', 'Aliases', (item) => Layer8DRenderers.renderTags(item.aliases || []), { sortKey: false }),
            ...col.enum('kind', 'Kind', TunEdge.enums.DOMAIN_KIND_VALUES, TunEdge.render.domainKind),
            ...col.custom('certStatus', 'Certificate', TunEdge.render.certBadge, { enumValues: TunEdge.enums.CERT_STATUS_VALUES }),
            ...col.custom('portForwards', 'Port forwards', (item) => esc(String((item.portForwards || []).length)), { sortKey: false }),
            ...col.boolean('enabled', 'Enabled'),
            ...col.custom('configVersion', 'On every edge', (item) => {
                if (TunEdge.appliedVersion === null) return '-';
                return Layer8DRenderers.renderBoolean(Number(item.configVersion || 0) <= TunEdge.appliedVersion,
                    { trueText: 'Applied', falseText: 'Pending', falseClass: 'layer8d-status-pending' });
            })
        ]
    };

    TunEdge.primaryKeys = { EdgeDomain: 'domainId' };
})();
