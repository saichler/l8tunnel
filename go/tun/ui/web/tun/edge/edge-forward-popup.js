// The Port forward popup of Edge ▸ Domains, desktop and mobile: a forward's
// Add, Edit and detail show its mode, its targets and how the edge
// balances over them. l8ui's row editor shows only the table's columns
// (protocol, in port, to port), so clicks on Add, Edit and (read-only) a
// row of the port forwards table open this popup instead; Delete stays
// l8ui's. The tunnel base's relay forwards come from cluster.yaml and keep
// l8ui's detail.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const e = TunEdge.enums;
    const RELAY = 3;

    const targetColumns = [
        { key: 'host', label: 'Host', type: 'text', required: true },
        { key: 'port', label: 'Port', type: 'number', required: true },
        { key: 'weight', label: 'Weight', type: 'number' },
        { key: 'disabled', label: 'Disabled', type: 'checkbox' }
    ];

    const formDef = f.form('Port forward', [
        f.section('Port forward', [
            ...f.select('protocol', 'Protocol', e.FORWARD_PROTOCOL, true),
            ...f.number('listenPort', 'In port', true),
            ...f.select('mode', 'Mode', { 1: 'Terminate', 2: 'Passthrough' }),
            ...f.number('targetPort', 'To port (on this node, when there are no targets)'),
            ...f.inlineTable('targets', 'Targets', targetColumns),
            ...f.select('lb', 'Balancing', e.LB),
            ...f.select('healthType', 'Health check', e.HEALTH),
            ...f.text('healthPath', 'Health check path (HTTP/HTTPS)'),
            ...f.number('healthInterval', 'Health check interval (seconds, 0 = 10)'),
            ...f.select('backendScheme', 'Backend scheme (Terminate)', e.BACKEND_SCHEME),
            ...f.checkbox('skipVerify', 'Skip backend certificate verification'),
            ...f.checkbox('proxyProtocol', 'Send PROXY protocol header'),
            ...f.checkbox('enabled', 'Enabled'),
            ...f.textarea('note', 'Note')
        ])
    ]);

    const num = (v) => Number(v) || 0;

    // forwardOf merges the popup's values onto the forward it edits, so
    // the fields it doesn't show (the ID, a port range, a DNS target) stay.
    function forwardOf(original, data) {
        const out = Object.assign({}, original, data);
        ['protocol', 'listenPort', 'mode', 'targetPort', 'lb', 'healthType', 'healthInterval', 'backendScheme']
            .forEach(k => { out[k] = num(out[k]); });
        out.targets = (data.targets || []).map(t => ({
            host: String(t.host || '').trim(), port: num(t.port), weight: num(t.weight), disabled: !!t.disabled
        }));
        return out;
    }

    // attachTargets wires the Targets table's own Add/Edit/Delete. l8ui
    // finds an inline table's definition in the current form context, so
    // the popup's form is the context while the handlers attach.
    function attachTargets(body) {
        const P = Layer8DFormsPickers;
        const saved = P.getFormContext();
        P.setFormContext(formDef);
        try {
            P.attachInlineTableHandlers(body);
        } finally {
            P.clearFormContext();
            if (saved) P.updateFormContext(saved);
        }
    }

    const titleOf = (readOnly, isNew) => readOnly ? 'Port forward details' : (isNew ? 'Add Port forward' : 'Edit Port forward');

    // openDesktop shows forward in the popup; onSave receives the edited
    // forward (none when readOnly).
    function openDesktop(forward, readOnly, isNew, onSave) {
        Layer8DPopup.show({
            title: titleOf(readOnly, isNew),
            content: Layer8DFormsFields.generateFormHtml(formDef, forward, { readOnly: readOnly }),
            size: 'large',
            showFooter: !readOnly,
            saveButtonText: isNew ? 'Add' : 'Update',
            onShow: (body) => {
                attachTargets(body);
                if (readOnly) body.querySelectorAll('input, select, textarea').forEach(el => { el.disabled = true; });
            },
            onSave: () => {
                const data = Layer8DFormsData.collectFormData(formDef);
                if (!data) return;
                onSave(forwardOf(forward, data));
                Layer8DPopup.close();
            }
        });
    }

    // redrawDesktop redraws the table's rows (the table keeps l8ui's
    // handlers).
    function redrawDesktop(table, rows) {
        const tmp = document.createElement('div');
        tmp.innerHTML = Layer8DFormsFields.generateInlineTableHtml(TunEdge.forwardsField, rows, false);
        table.querySelector('.form-inline-table-body').innerHTML = tmp.querySelector('.form-inline-table-body').innerHTML;
    }

    // openMobile is openDesktop for the mobile shell, whose forms wire
    // their inline tables from the form definition.
    function openMobile(forward, readOnly, isNew, onSave) {
        const M = Layer8MForms;
        Layer8MPopup.show({
            title: titleOf(readOnly, isNew),
            content: M.renderForm(formDef, forward, readOnly),
            size: 'large',
            showFooter: !readOnly,
            saveButtonText: isNew ? 'Add' : 'Update',
            onShow: (popup) => {
                M.initFormFields(popup.body, formDef);
                if (readOnly) popup.body.querySelectorAll('input, select, textarea').forEach(el => { el.disabled = true; });
            },
            onSave: (popup) => {
                onSave(forwardOf(forward, M.getFormData(popup.body)));
                Layer8MPopup.close();
            }
        });
    }

    // The two shells' port forwards tables.
    const shells = [
        {
            table: '.form-inline-table[data-inline-table="portForwards"]', row: '.form-inline-table-row',
            readOnly: (t) => t.classList.contains('form-inline-table-readonly'), open: openDesktop, redraw: redrawDesktop
        },
        {
            table: '.mobile-form-inline-table[data-inline-table="portForwards"]', row: '.mobile-form-inline-card',
            readOnly: (t) => t.querySelector('.l8-clickable-row') !== null, open: openMobile,
            redraw: (t, rows) => Layer8MForms._rerenderMobileTable(t, TunEdge.forwardsField, rows, false)
        }
    ];

    // Capture phase: runs before l8ui's handler on the table, which it
    // stops for the clicks the popup takes over.
    document.addEventListener('click', (ev) => {
        let shell = null, table = null;
        for (const sh of shells) {
            table = ev.target.closest(sh.table);
            if (table) { shell = sh; break; }
        }
        if (!table) return;
        const input = table.querySelector('input[data-inline-table-data="portForwards"]');
        const rows = () => Layer8InlineTableState.getRows(input);
        const btn = ev.target.closest('[data-action]');
        if (btn) {
            const action = btn.dataset.action;
            if (action !== 'add-row' && action !== 'edit-row') return;
            const idx = action === 'add-row' ? -1 : parseInt(btn.dataset.rowIndex, 10);
            const forward = idx >= 0 ? rows()[idx] : { enabled: true };
            if (!forward || forward.mode === RELAY) return;
            ev.stopPropagation();
            ev.preventDefault();
            shell.open(forward, false, idx < 0, (saved) => {
                const all = rows();
                if (idx < 0) all.push(saved); else all[idx] = saved;
                Layer8InlineTableState.setRows(input, all);
                shell.redraw(table, all);
            });
            return;
        }
        const rowEl = ev.target.closest(shell.row);
        if (!rowEl || !shell.readOnly(table)) return;
        const forward = rows()[parseInt(rowEl.dataset.rowIndex, 10)];
        if (!forward || forward.mode === RELAY) return;
        ev.stopPropagation();
        shell.open(forward, true, false);
    }, true);
})();
