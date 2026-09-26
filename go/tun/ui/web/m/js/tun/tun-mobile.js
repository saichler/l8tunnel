// Mobile wiring of the l8tunnel behavior, over the same cores as desktop
// (tun-actions-core, tun-issue-core): record details with their actions,
// an agent's tunnels, the show-once issuing, the token and edge domain
// rules, and the router ports view. The nav config (layer8m-nav-config-
// tun.js) points its services' handlers here.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;
    const activeTable = () => window._Layer8MNavActiveTable;

    // service finds a nav service config by its key.
    function service(key) {
        for (const mod of LAYER8M_NAV_CONFIG.modules) {
            const cfg = LAYER8M_NAV_CONFIG[mod.key];
            if (!cfg || !cfg.services) continue;
            for (const list of Object.values(cfg.services)) {
                const s = list.find(x => x.key === key);
                if (s) return s;
            }
        }
        throw new Error('no l8tunnel mobile service ' + key);
    }

    function formDef(svc, record) {
        if (svc.model === 'EdgeDomain') {
            return TunActionsCore.isTunnelBase(record) ? TunEdge.tunnelBaseForm : TunEdge.editForm;
        }
        return Layer8MNavData.getServiceFormDef(svc);
    }

    // canEdit mirrors the nav's own rule: not read-only, and PUT allowed.
    function canEdit(svc) {
        if (svc.readOnly) return false;
        const perms = window.Layer8DPermissions;
        if (!perms || Object.keys(perms).length === 0) return true;
        return (perms[svc.model] || []).indexOf(2) !== -1;
    }

    function actionBarHtml(specs) {
        if (!specs || specs.length === 0) return '';
        return '<div class="tun-action-bar">' + specs.map((s, i) =>
            '<button type="button" class="layer8d-btn layer8d-btn-small layer8d-btn-secondary' + (s.danger ? ' tun-danger' : '') +
            '" data-tun-action="' + i + '">' + esc(s.label) + '</button>').join('') + '</div>';
    }

    function wireActions(body, specs) {
        body.querySelectorAll('[data-tun-action]').forEach(btn => btn.addEventListener('click', async () => {
            const spec = specs[Number(btn.dataset.tunAction)];
            if (spec.open) return openRecord(spec.open.service, spec.open.id);
            if (spec.invoke === 'issueCert') return issueCert(spec.record);
            if (spec.confirm && !(await Layer8MConfirm.show({ title: spec.label, message: spec.confirm,
                confirmText: spec.label, destructive: !!spec.danger }))) return;
            try {
                Layer8MUtils.showSuccess(await spec.run());
                Layer8MPopup.close();
                if (activeTable()) activeTable().refresh();
            } catch (e) {
                Layer8MUtils.showError(spec.label + ' failed: ' + e.message);
            }
        }));
    }

    // agentTunnels lists an agent's live tunnels under its details.
    async function agentTunnels(body, agentId) {
        const holder = document.createElement('div');
        holder.className = 'tun-related';
        holder.innerHTML = '<h3 class="tun-related-title">Tunnels</h3><div class="tun-muted">Loading...</div>';
        body.appendChild(holder);
        let rows;
        try {
            rows = await TunData.list('/42/TunLive', 'TunLiveTunnel', TunActionsCore.agentTunnelsWhere(agentId));
        } catch (e) {
            holder.lastChild.textContent = 'Tunnels unavailable: ' + e.message;
            return;
        }
        if (rows.length === 0) {
            holder.lastChild.textContent = 'No tunnels';
            return;
        }
        holder.lastChild.outerHTML = rows.map(t =>
            '<div class="mobile-table-card" data-tunnel="' + esc(t.name) + '">' +
            '<h4 class="mobile-table-card-title">' + esc(t.name) + '</h4>' +
            '<p class="mobile-table-card-subtitle">' + TunLive.render.liveState(t.state) + ' ' + TunLive.render.tunnelType(t.type) + '</p></div>').join('');
        holder.querySelectorAll('[data-tunnel]').forEach(card =>
            card.addEventListener('click', () => openRecord('live', card.dataset.tunnel)));
    }

    // details shows a record read-only, as Layer8MNavCrud.showRecordDetails
    // does, with the record's actions on top and Edit when it's editable.
    async function details(svc, item) {
        const record = await Layer8MNavCrud.fetchRecord(svc, item[svc.idField]);
        if (!record) {
            Layer8MUtils.showError('Record not found');
            return;
        }
        const def = formDef(svc, record);
        const specs = TunActionsCore.forModel(svc.model, record) || [];
        const editable = canEdit(svc);
        Layer8MPopup.show({
            title: svc.label.replace(/s$/, '') + ' Details',
            content: actionBarHtml(specs) + Layer8MForms.renderForm(def, record, true),
            size: 'large',
            showFooter: editable,
            saveButtonText: 'Edit',
            showCancelButton: true,
            cancelButtonText: 'Close',
            onShow: (popup) => {
                Layer8MForms.initFormFields(popup.body, def);
                popup.body.querySelectorAll('input, select, textarea').forEach(el => { el.disabled = true; });
                Layer8MForms.wireTabSwitching(popup.body);
                wireActions(popup.body, specs);
                if (svc.model === 'TunAgent') agentTunnels(popup.body, record.agentId);
            },
            onSave: () => {
                Layer8MPopup.close();
                Layer8MNavCrud.openServiceForm(svc, def, record);
            }
        });
    }

    function openRecord(key, id) {
        if (!id) return;
        const svc = service(key);
        details(svc, { [svc.idField]: id });
    }

    // formPopup shows a form and calls onSubmit with its data; onSubmit
    // returns the show-once content that replaces the form.
    function formPopup(title, def, onSubmit) {
        Layer8MPopup.show({
            title: title,
            content: Layer8MForms.renderForm(def, {}),
            size: 'large',
            saveButtonText: 'Issue',
            onShow: (popup) => Layer8MForms.initFormFields(popup.body, def),
            onSave: async (popup) => {
                const errors = Layer8MForms.validateForm(popup.body);
                if (errors.length) return Layer8MForms.showErrors(popup.body, errors);
                try {
                    const content = await onSubmit(Layer8MForms.getFormData(popup.body));
                    Layer8MPopup.close();
                    Layer8MPopup.show({
                        title: content.title, content: content.html, size: 'large', showFooter: false,
                        onShow: (p) => TunIssueCore.wireSecrets(p.body, () => Layer8MUtils.showSuccess('Copied'))
                    });
                } catch (e) {
                    Layer8MUtils.showError(title + ' failed: ' + e.message);
                }
            }
        });
    }

    function issueToken() {
        formPopup('Issue token', TunIssueCore.tokenForm, async (data) => {
            const content = await TunIssueCore.issueToken(data);
            if (activeTable()) activeTable().refresh();
            return content;
        });
    }

    function issueCert(token) {
        formPopup('Issue certificate for ' + token.name, TunIssueCore.certForm, (data) => TunIssueCore.issueCert(token, data));
    }

    async function revokeToken(id) {
        if (!(await Layer8MConfirm.show({ title: 'Revoke token', message: TunIssueCore.REVOKE_CONFIRM,
            confirmText: 'Revoke', destructive: true }))) return;
        try {
            Layer8MUtils.showSuccess(await TunIssueCore.revoke(id));
            if (activeTable()) activeTable().refresh();
        } catch (e) {
            Layer8MUtils.showError('Revoke failed: ' + e.message);
        }
    }

    async function editDomain(id, item) {
        const svc = service('domains');
        const record = await Layer8MNavCrud.fetchRecord(svc, id);
        Layer8MNavCrud.openServiceForm(svc, formDef(svc, record), record || item);
    }

    async function deleteDomain(id, item) {
        const svc = service('domains');
        if (TunActionsCore.isTunnelBase(await Layer8MNavCrud.fetchRecord(svc, id))) {
            return Layer8MUtils.showError(TunActionsCore.TUNNEL_BASE_DELETE);
        }
        Layer8MNavCrud.deleteServiceRecord(svc, id, item);
    }

    // routerPorts is the custom view of Edge > Router ports: one card per
    // listener the edges report.
    const routerPorts = {
        initialize: async function() {
            const box = document.getElementById('tun-m-router-ports');
            if (!box) return;
            box.innerHTML = '<div class="tun-muted">Loading...</div>';
            let nodes;
            try {
                nodes = TunData.liveEdges(await TunData.list('/41/EdgeNode', 'EdgeNode'));
            } catch (e) {
                box.innerHTML = '<div class="tun-muted">Edge reports unavailable: ' + esc(e.message) + '</div>';
                return;
            }
            const rows = [];
            nodes.forEach(n => (n.listeners || []).forEach(l => rows.push({ n: n, l: l })));
            rows.sort((a, b) => Number(a.l.port) - Number(b.l.port));
            box.innerHTML = rows.length === 0 ? '<div class="tun-muted">No edge has reported in the last two minutes.</div>' :
                rows.map(r => '<div class="mobile-table-card">' +
                    '<h4 class="mobile-table-card-title">' + esc(r.l.portEnd ? r.l.port + '-' + r.l.portEnd : String(r.l.port)) +
                    ' ' + TunEdge.render.protocol(r.l.protocol) + '</h4>' +
                    '<p class="mobile-table-card-subtitle">' + (r.l.bound
                        ? '<span class="layer8d-status layer8d-status-active">Bound</span>'
                        : '<span class="layer8d-status layer8d-status-terminated">' + esc(r.l.error || 'Not bound') + '</span>') + '</p>' +
                    '<p class="tun-muted">' + esc((r.l.domains || []).join(', ')) + ' · ' + esc(r.n.edgeId) + '</p></div>').join('');
        }
    };

    window.TunMobile = {
        details: details, openRecord: openRecord,
        issueToken: issueToken, revokeToken: revokeToken,
        editDomain: editDomain, deleteDomain: deleteDomain
    };
    window.TunRouterPortsM = routerPorts;
})();
