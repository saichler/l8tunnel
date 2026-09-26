// Actions on the l8tunnel records: the operator commands on the live
// tables (disconnect, drain, resume), certificate revocation, opening a
// related record, and the edge domain's per-row form. They wrap the Tun
// namespace's CRUD handlers (install() is called by tun-init.js) and add
// buttons to the standard detail popup, so its rendering stays the
// canonical one.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;

    // send sends a JSON body to an l8tunnel endpoint and returns the
    // parsed response; a failure throws with the server's message.
    async function send(method, endpoint, body) {
        const resp = await fetch(Layer8DConfig.resolveEndpoint(endpoint), {
            method: method, headers: getAuthHeaders(), body: JSON.stringify(body)
        });
        const text = await resp.text();
        if (!resp.ok) throw new Error(text || ('HTTP ' + resp.status));
        return text ? JSON.parse(text) : {};
    }

    function currentUser() {
        return sessionStorage.getItem('currentUser') || '';
    }

    // service finds a Tun service config by its key.
    function service(key) {
        for (const m of Object.values(Tun.modules)) {
            const s = m.services.find(x => x.key === key);
            if (s) return s;
        }
        throw new Error('no Tun service ' + key);
    }

    // actionBar adds buttons at the top of the topmost popup.
    function actionBar(buttons) {
        const body = Layer8DPopup.getBody();
        if (!body || buttons.length === 0) return;
        const bar = document.createElement('div');
        bar.className = 'tun-action-bar';
        buttons.forEach(b => {
            const btn = document.createElement('button');
            btn.type = 'button';
            btn.className = 'layer8d-btn layer8d-btn-small ' + (b.danger ? 'layer8d-btn-secondary tun-danger' : 'layer8d-btn-secondary');
            btn.textContent = b.label;
            btn.addEventListener('click', b.onClick);
            bar.appendChild(btn);
        });
        body.insertBefore(bar, body.firstChild);
    }

    // command confirms and sends an operator command through TunCtl.
    function command(label, confirmText, cmd) {
        return {
            label: label, danger: true, onClick: async () => {
                if (!window.confirm(confirmText)) return;
                try {
                    await send('POST', Tun.CTL_ENDPOINT, Object.assign({ requestedBy: currentUser() }, cmd));
                    Layer8DNotification.success(label + ': done');
                    Layer8DPopup.close();
                    Tun.refreshCurrentTable();
                } catch (e) {
                    Layer8DNotification.error(label + ' failed', [e.message]);
                }
            }
        };
    }

    const open = (label, key, id) => ({ label: label, onClick: () => openRecord(key, id) });

    // openRecord shows a record's detail popup by its service key and ID.
    function openRecord(key, id) {
        if (!id) return;
        const svc = service(key);
        const pk = Layer8DServiceRegistry.getPrimaryKey('Tun', svc.model);
        Tun._showDetailsModal(svc, { [pk]: id }, id);
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
        const table = new Layer8DTable({
            containerId: id,
            endpoint: Layer8DConfig.resolveEndpoint('/42/TunLive'),
            modelName: 'TunLiveTunnel',
            columns: TunLive.columns.TunLiveTunnel,
            primaryKey: 'name',
            pageSize: 5,
            baseWhereClause: 'agentId=' + agentId,
            onRowClick: (item) => openRecord('live', item.name),
            emptyMessage: 'No tunnels'
        });
        table.init();
    }

    // Buttons per model on the detail popup.
    const detailActions = {
        TunAgent: (d) => {
            const b = [];
            if (Number(d.state) === 1) {
                b.push(command('Disconnect agent', 'Disconnect agent ' + d.agentId + '? Every tunnel of the session closes; the agent reconnects on its own.',
                    { kind: 4, agentId: d.agentId }));
            }
            if (d.tokenId) b.push(open('Open token', 'tokens', d.tokenId));
            return b;
        },
        TunLiveTunnel: (d) => {
            const b = [];
            if (Number(d.state) === 1) {
                b.push(command('Disconnect', 'Disconnect tunnel ' + d.name + '?', { kind: 5, tunnelId: d.tunnelId }));
            }
            if (d.agentId) b.push(open('Open agent', 'agents', d.agentId));
            return b;
        },
        TunRelay: (d) => {
            const state = Number(d.state);
            if (state === 1) {
                return [command('Drain', 'Drain relay ' + d.relayId + '? It takes no new agents and its agents move to the other relays.',
                    { kind: 2, relayId: d.relayId })];
            }
            if (state === 2) return [command('Resume', 'Resume relay ' + d.relayId + '?', { kind: 3, relayId: d.relayId })];
            return [];
        },
        TunToken: (d) => [{ label: 'Issue certificate', onClick: () => TunIssue.openIssueCert(d) }],
        TunAgentCert: (d) => d.revoked ? [] : [{
            label: 'Revoke', danger: true, onClick: async () => {
                if (!window.confirm('Revoke certificate ' + d.certId + '? Agents using it are refused from now on.')) return;
                try {
                    await send('PATCH', service('agentcerts').endpoint, { certId: d.certId, revoked: true });
                    Layer8DNotification.success('Certificate revoked');
                    Layer8DPopup.close();
                    Tun.refreshCurrentTable();
                } catch (e) {
                    Layer8DNotification.error('Revoke failed', [e.message]);
                }
            }
        }]
    };

    // fetchRecord loads a record the way the detail popup does.
    async function fetchRecord(svc, id) {
        const pk = Layer8DServiceRegistry.getPrimaryKey('Tun', svc.model);
        return Layer8DFormsData.fetchRecord(Layer8DConfig.resolveEndpoint(svc.endpoint), pk, id, svc.model);
    }

    function install() {
        const origDetails = Tun._showDetailsModal;
        Tun._showDetailsModal = async function(svc, item, id) {
            await origDetails.call(Tun, svc, item, id);
            const actions = detailActions[svc.model];
            if (!actions) return;
            const data = id ? (await fetchRecord(svc, id)) || item : item;
            // The popup disables its inputs 50 ms after it renders; add the
            // agent's tunnels table after that, or its controls go dead.
            await new Promise(r => setTimeout(r, 80));
            actionBar(actions(data));
            if (svc.model === 'TunAgent') agentTunnels(data.agentId);
        };

        // An existing domain can't change its kind, and the TUNNEL_BASE
        // row's names and forwards come from cluster.yaml.
        const origEdit = Tun._openEditModal;
        Tun._openEditModal = async function(svc, id) {
            if (svc.model !== 'EdgeDomain') return origEdit.call(Tun, svc, id);
            const rec = await fetchRecord(svc, id);
            const formDef = rec && Number(rec.kind) === 2 ? TunEdge.tunnelBaseForm : TunEdge.editForm;
            Layer8DForms.openEditForm({
                endpoint: Layer8DConfig.resolveEndpoint(svc.endpoint), primaryKey: 'domainId', modelName: svc.model
            }, formDef, id, () => Tun.refreshCurrentTable());
        };

        const origAdd = Tun._openAddModal;
        Tun._openAddModal = function(svc) {
            if (svc.model === 'TunToken') return TunIssue.openIssueToken(() => Tun.refreshCurrentTable());
            return origAdd.call(Tun, svc);
        };

        // Deleting a token revokes it through TunIssue: its certificates
        // and reservations go too, and every relay drops its sessions at
        // once (a plain ORM DELETE runs no callbacks).
        const origDelete = Tun._confirmDeleteItem;
        Tun._confirmDeleteItem = function(svc, id) {
            if (svc.model !== 'TunToken') return origDelete.call(Tun, svc, id);
            TunIssue.revokeToken(id, () => Tun.refreshCurrentTable());
        };

        hideKeyDownloads();
    }

    // hideKeyDownloads removes the download button of a domain's private
    // key wherever a form renders it: the UI never offers a key download
    // (plan §5.6), and l8ui's file field has no option to leave it out.
    function hideKeyDownloads() {
        const strip = (root) => root.querySelectorAll('label[for="field-keyStoragePath"]').forEach(label => {
            const group = label.closest('.form-group');
            if (group) group.querySelectorAll('.l8-file-download-btn').forEach(btn => btn.remove());
        });
        new MutationObserver((mutations) => {
            for (const m of mutations) {
                m.addedNodes.forEach(n => { if (n.nodeType === 1) strip(n); });
            }
        }).observe(document.body, { childList: true, subtree: true });
    }

    window.TunActions = { install: install, openRecord: openRecord, send: send, service: service, esc: esc };
})();
