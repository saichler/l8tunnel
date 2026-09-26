// The show-once issuing of TunIssue, shared by both shells: a new token's
// plaintext and a new agent certificate's private key are returned once
// and never stored readable, so they're shown right away, with copy and
// download. The shells supply the popups.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const esc = Layer8DUtils.escapeHtml;
    const KIND = { TOKEN: 1, AGENT_CERT: 2, REVOKE: 4 };

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

    window.TunIssueCore = {
        tokenForm: f.form('Issue token', [
            f.section('Token', [
                ...f.text('tokenName', 'Name', true),
                ...f.textarea('tokenDescription', 'Description')
            ]),
            f.section('Policy', TunAccess.policyFields())
        ]),

        certForm: f.form('Issue agent certificate', [
            f.section('Certificate', [...f.number('certDays', 'Valid for (days, 0 = the default)')])
        ]),

        // issueToken returns the show-once content for a new token.
        issueToken: async function(data) {
            const resp = await TunData.request('POST', TunData.ISSUE_ENDPOINT, {
                kind: KIND.TOKEN, tokenName: data.tokenName, tokenDescription: data.tokenDescription || '',
                policy: data.policy || {}
            });
            return {
                title: 'Token ' + data.tokenName,
                html: '<p class="tun-once-warning">This is the only time the token is shown. Copy it now; only its hash is stored.</p>' +
                    secretBlock('Token', resp.token || '')
            };
        },

        // issueCert returns the show-once content for a new certificate.
        issueCert: async function(token, data) {
            const resp = await TunData.request('POST', TunData.ISSUE_ENDPOINT, {
                kind: KIND.AGENT_CERT, tokenId: token.tokenId, certDays: data.certDays || 0
            });
            return {
                title: 'Certificate ' + resp.certId,
                html: '<p class="tun-once-warning">This is the only time the private key is shown. Download both files now; the key isn\'t stored.</p>' +
                    secretBlock('Certificate', resp.certPem || '', token.name + '.crt') +
                    secretBlock('Private key', resp.keyPem || '', token.name + '.key')
            };
        },

        REVOKE_CONFIRM: 'Revoke this token? Its certificates and reservations are removed, and its agents are disconnected.',

        // revoke revokes a token and returns the success message.
        revoke: async function(tokenId) {
            const resp = await TunData.request('POST', TunData.ISSUE_ENDPOINT, { kind: KIND.REVOKE, tokenId: tokenId });
            return 'Token revoked (' + (resp.revokedCerts || 0) + ' certificates, ' +
                (resp.removedReservations || 0) + ' reservations removed)';
        },

        // wireSecrets connects the copy and download buttons of the
        // show-once content.
        wireSecrets: function(body, onCopied) {
            body.querySelectorAll('.tun-secret').forEach(block => {
                const value = block.querySelector('.tun-secret-value').value;
                block.querySelector('[data-copy]').addEventListener('click', async () => {
                    await navigator.clipboard.writeText(value);
                    onCopied();
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
    };
})();
