// The show-once flows of TunIssue: a new token's plaintext and a new agent
// certificate's private key are returned once and never stored readable,
// so they're shown (and offered for copy or download) right away.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const esc = Layer8DUtils.escapeHtml;
    const KIND = { TOKEN: 1, AGENT_CERT: 2, REVOKE: 4 };

    const issueTokenForm = f.form('Issue token', [
        f.section('Token', [
            ...f.text('tokenName', 'Name', true),
            ...f.textarea('tokenDescription', 'Description')
        ]),
        f.section('Policy', TunAccess.policyFields())
    ]);

    const issueCertForm = f.form('Issue agent certificate', [
        f.section('Certificate', [
            ...f.number('certDays', 'Valid for (days, 0 = the default)')
        ])
    ]);

    // formPopup shows a form and calls onSubmit with its collected data.
    function formPopup(title, formDef, saveText, onSubmit) {
        Layer8DPopup.show({
            title: title,
            content: Layer8DForms.generateFormHtml(formDef, {}),
            size: 'large',
            showFooter: true,
            saveButtonText: saveText,
            onShow: (body) => Layer8DForms.attachDatePickers(body),
            onSave: async () => {
                const data = Layer8DFormsData.collectFormData(formDef);
                if (!data) return;
                const errors = Layer8DFormsData.validateFormData(formDef, data);
                if (errors.length) {
                    Layer8DNotification.error('Check the form', errors.map(e => e.message));
                    return;
                }
                try {
                    await onSubmit(data);
                } catch (e) {
                    Layer8DNotification.error(title + ' failed', [e.message]);
                }
            }
        });
    }

    // secretBlock is a read-only box with a copy (and optional download)
    // button.
    function secretBlock(label, value, fileName) {
        return '<div class="tun-secret">' +
            '<label>' + esc(label) + '</label>' +
            '<textarea class="tun-secret-value" readonly rows="' + (value.includes('\n') ? 8 : 2) + '">' + esc(value) + '</textarea>' +
            '<div class="tun-secret-actions">' +
            '<button type="button" class="layer8d-btn layer8d-btn-small layer8d-btn-secondary" data-copy>Copy</button>' +
            (fileName ? '<button type="button" class="layer8d-btn layer8d-btn-small layer8d-btn-secondary" data-download="' +
                esc(fileName) + '">Download</button>' : '') +
            '</div></div>';
    }

    function wireSecrets(body) {
        body.querySelectorAll('.tun-secret').forEach(block => {
            const value = block.querySelector('.tun-secret-value').value;
            block.querySelector('[data-copy]').addEventListener('click', async () => {
                await navigator.clipboard.writeText(value);
                Layer8DNotification.success('Copied');
            });
            const dl = block.querySelector('[data-download]');
            if (dl) dl.addEventListener('click', () => {
                const a = document.createElement('a');
                a.href = URL.createObjectURL(new Blob([value], { type: 'application/x-pem-file' }));
                a.download = dl.dataset.download;
                a.click();
                URL.revokeObjectURL(a.href);
            });
        });
    }

    // showOnce replaces the form with the secrets; closing it is final.
    function showOnce(title, intro, blocks) {
        Layer8DPopup.close();
        Layer8DPopup.show({
            title: title,
            content: '<p class="tun-once-warning">' + esc(intro) + '</p>' + blocks.join(''),
            size: 'large',
            showFooter: false,
            onShow: wireSecrets
        });
    }

    function openIssueToken(onDone) {
        formPopup('Issue token', issueTokenForm, 'Issue', async (data) => {
            const resp = await TunActions.send('POST', Tun.ISSUE_ENDPOINT, {
                kind: KIND.TOKEN, tokenName: data.tokenName, tokenDescription: data.tokenDescription || '',
                policy: data.policy || {}
            });
            showOnce('Token ' + data.tokenName, 'This is the only time the token is shown. Copy it now; ' +
                'only its hash is stored.', [secretBlock('Token', resp.token || '')]);
            onDone();
        });
    }

    function openIssueCert(token) {
        formPopup('Issue certificate for ' + token.name, issueCertForm, 'Issue', async (data) => {
            const resp = await TunActions.send('POST', Tun.ISSUE_ENDPOINT, {
                kind: KIND.AGENT_CERT, tokenId: token.tokenId, certDays: data.certDays || 0
            });
            showOnce('Certificate ' + resp.certId, 'This is the only time the private key is shown. ' +
                'Download both files now; the key isn\'t stored.', [
                secretBlock('Certificate', resp.certPem || '', token.name + '.crt'),
                secretBlock('Private key', resp.keyPem || '', token.name + '.key')
            ]);
        });
    }

    async function revokeToken(tokenId, onDone) {
        if (!window.confirm('Revoke this token? Its certificates and reservations are removed, and its agents are disconnected.')) return;
        try {
            const resp = await TunActions.send('POST', Tun.ISSUE_ENDPOINT, { kind: KIND.REVOKE, tokenId: tokenId });
            Layer8DNotification.success('Token revoked (' + (resp.revokedCerts || 0) + ' certificates, ' +
                (resp.removedReservations || 0) + ' reservations removed)');
            onDone();
        } catch (e) {
            Layer8DNotification.error('Revoke failed', [e.message]);
        }
    }

    window.TunIssue = { openIssueToken: openIssueToken, openIssueCert: openIssueCert, revokeToken: revokeToken };
})();
