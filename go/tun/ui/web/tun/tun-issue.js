// Desktop popups of the show-once issuing (tun-issue-core.js).
(function() {
    'use strict';

    // formPopup shows a form and calls onSubmit with its collected data.
    function formPopup(title, formDef, onSubmit) {
        Layer8DPopup.show({
            title: title,
            content: Layer8DForms.generateFormHtml(formDef, {}),
            size: 'large',
            showFooter: true,
            saveButtonText: 'Issue',
            onShow: (body) => Layer8DForms.attachDatePickers(body),
            onSave: async () => {
                const data = Layer8DFormsData.collectFormData(formDef);
                if (!data) return;
                const errors = Layer8DFormsData.validateFormData(formDef, data);
                if (errors.length) return Layer8DNotification.error('Check the form', errors.map(e => e.message));
                try {
                    showOnce(await onSubmit(data));
                } catch (e) {
                    Layer8DNotification.error(title + ' failed', [e.message]);
                }
            }
        });
    }

    // showOnce replaces the form with the secrets; closing it is final.
    function showOnce(content) {
        Layer8DPopup.close();
        Layer8DPopup.show({
            title: content.title, content: content.html, size: 'large', showFooter: false,
            onShow: (body) => TunIssueCore.wireSecrets(body, () => Layer8DNotification.success('Copied'))
        });
    }

    window.TunIssue = {
        openIssueToken: function(onDone) {
            formPopup('Issue token', TunIssueCore.tokenForm, async (data) => {
                const content = await TunIssueCore.issueToken(data);
                onDone();
                return content;
            });
        },
        openIssueCert: function(token) {
            formPopup('Issue certificate for ' + token.name, TunIssueCore.certForm, (data) => TunIssueCore.issueCert(token, data));
        },
        revokeToken: async function(tokenId, onDone) {
            if (!window.confirm(TunIssueCore.REVOKE_CONFIRM)) return;
            try {
                Layer8DNotification.success(await TunIssueCore.revoke(tokenId));
                onDone();
            } catch (e) {
                Layer8DNotification.error('Revoke failed', [e.message]);
            }
        }
    };
})();
