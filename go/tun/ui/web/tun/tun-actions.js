// Desktop wiring of the l8tunnel actions (tun-actions-core.js): buttons on
// the standard detail popup, an agent's tunnels under its details, the
// edge domain's per-row form and delete rule, and hiding the private-key
// download. install() wraps the Tun namespace's CRUD handlers, so the
// popup's rendering stays the canonical one.
(function() {
    'use strict';

    // service finds a Tun service config by its key.
    function service(key) {
        for (const m of Object.values(Tun.modules)) {
            const s = m.services.find(x => x.key === key);
            if (s) return s;
        }
        throw new Error('no Tun service ' + key);
    }

    // openRecord shows a record's detail popup by its service key and ID.
    function openRecord(key, id) {
        if (!id) return;
        const svc = service(key);
        const pk = Layer8DServiceRegistry.getPrimaryKey('Tun', svc.model);
        Tun._showDetailsModal(svc, { [pk]: id }, id);
    }

    function onAction(spec) {
        if (spec.open) return openRecord(spec.open.service, spec.open.id);
        if (spec.invoke === 'issueCert') return TunIssue.openIssueCert(spec.record);
        if (spec.invoke === 'connect') return showConnect(spec.record);
        return async () => {};
    }

    // showConnect shows the commands that reach an SSH or TCP tunnel.
    function showConnect(tunnel) {
        Layer8DPopup.show({
            title: TunConnect.title(tunnel), content: TunConnect.html(tunnel), size: 'medium', showFooter: false,
            onShow: (body) => TunConnect.wire(body, tunnel, () => Layer8DNotification.success('Copied'))
        });
    }

    // actionBar adds the action buttons at the top of the topmost popup.
    function actionBar(specs) {
        const body = Layer8DPopup.getBody();
        if (!body || specs.length === 0) return;
        const bar = document.createElement('div');
        bar.className = 'tun-action-bar';
        specs.forEach(spec => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'layer8d-btn layer8d-btn-small layer8d-btn-secondary' + (spec.danger ? ' tun-danger' : '');
            btn.textContent = spec.label;
            btn.addEventListener('click', async () => {
                if (!spec.run) return onAction(spec);
                if (spec.confirm && !window.confirm(spec.confirm)) return;
                try {
                    Layer8DNotification.success(await spec.run());
                    Layer8DPopup.close();
                    Tun.refreshCurrentTable();
                } catch (e) {
                    Layer8DNotification.error(spec.label + ' failed', [e.message]);
                }
            });
            bar.appendChild(btn);
        });
        body.insertBefore(bar, body.firstChild);
    }

    // agentTunnels shows an agent's live tunnels under its details.
    function agentTunnels(agentId) {
        const body = Layer8DPopup.getBody();
        if (!body) return;
        const holder = document.createElement('div');
        holder.className = 'tun-related';
        const id = 'tun-agent-tunnels-' + Math.random().toString(36).slice(2);
        holder.innerHTML = '<h3 class="tun-related-title">Tunnels</h3><div id="' + id + '"></div>';
        body.appendChild(holder);
        new Layer8DTable({
            containerId: id,
            endpoint: Layer8DConfig.resolveEndpoint('/42/TunLive'),
            modelName: 'TunLiveTunnel',
            columns: TunLive.columns.TunLiveTunnel,
            primaryKey: 'name',
            pageSize: 5,
            serverSide: true,
            baseWhereClause: TunActionsCore.agentTunnelsWhere(agentId),
            onRowClick: (item) => openRecord('live', item.name),
            emptyMessage: 'No tunnels'
        }).init();
    }

    async function fetchRecord(svc, id) {
        const pk = Layer8DServiceRegistry.getPrimaryKey('Tun', svc.model);
        return Layer8DFormsData.fetchRecord(Layer8DConfig.resolveEndpoint(svc.endpoint), pk, id, svc.model);
    }

    function install() {
        const origDetails = Tun._showDetailsModal;
        Tun._showDetailsModal = async function(svc, item, id) {
            await origDetails.call(Tun, svc, item, id);
            if (!TunActionsCore.forModel(svc.model, {})) return;
            const data = id ? (await fetchRecord(svc, id)) || item : item;
            // The popup disables its inputs 50 ms after it renders; add the
            // agent's tunnels table after that, or its controls go dead.
            await new Promise(r => setTimeout(r, 80));
            actionBar(TunActionsCore.forModel(svc.model, data));
            if (svc.model === 'TunAgent') agentTunnels(data.agentId);
        };

        // An existing domain can't change its kind, and the TUNNEL_BASE
        // row's names and forwards come from cluster.yaml.
        const origEdit = Tun._openEditModal;
        Tun._openEditModal = async function(svc, id) {
            if (svc.model !== 'EdgeDomain') return origEdit.call(Tun, svc, id);
            const rec = await fetchRecord(svc, id);
            Layer8DForms.openEditForm({
                endpoint: Layer8DConfig.resolveEndpoint(svc.endpoint), primaryKey: 'domainId', modelName: svc.model
            }, TunActionsCore.isTunnelBase(rec) ? TunEdge.tunnelBaseForm : TunEdge.editForm, id, () => Tun.refreshCurrentTable());
        };

        const origAdd = Tun._openAddModal;
        Tun._openAddModal = function(svc) {
            if (svc.model === 'TunToken') return TunIssue.openIssueToken(() => Tun.refreshCurrentTable());
            return origAdd.call(Tun, svc);
        };

        // Deleting a token revokes it through TunIssue (its certificates
        // and reservations go too, and every relay drops its sessions at
        // once); the TUNNEL_BASE domain can't be deleted.
        const origDelete = Tun._confirmDeleteItem;
        Tun._confirmDeleteItem = async function(svc, id) {
            if (svc.model === 'TunToken') return TunIssue.revokeToken(id, () => Tun.refreshCurrentTable());
            if (svc.model === 'EdgeDomain' && TunActionsCore.isTunnelBase(await fetchRecord(svc, id))) {
                return Layer8DNotification.warning(TunActionsCore.TUNNEL_BASE_DELETE);
            }
            return origDelete.call(Tun, svc, id);
        };

        TunKeyDownload.hide();
    }

    window.TunActions = { install: install, openRecord: openRecord };
})();
