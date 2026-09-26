// Removes the download button of an edge domain's private key wherever a
// form renders it, on both shells: the UI never offers a key download
// (plan §5.6), and l8ui's file field has no option to leave it out.
(function() {
    'use strict';

    function strip(root) {
        root.querySelectorAll('[for="field-keyStoragePath"], [data-field-key="keyStoragePath"]').forEach(el => {
            const group = el.closest('.form-group, .mobile-form-field');
            if (group) group.querySelectorAll('.l8-file-download-btn').forEach(btn => btn.remove());
        });
    }

    window.TunKeyDownload = {
        hide: function() {
            new MutationObserver((mutations) => {
                for (const m of mutations) m.addedNodes.forEach(n => { if (n.nodeType === 1) strip(n); });
            }).observe(document.body, { childList: true, subtree: true });
        }
    };
})();
