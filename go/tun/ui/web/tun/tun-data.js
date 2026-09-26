// The l8tunnel HTTP layer, shared by the desktop and mobile shells: JSON
// requests to the l8tunnel services and whole-table reads for the views
// that aggregate them (dashboard, router ports, version and applied-config
// badges). Each shell sets TunData.resolve to its config's endpoint
// resolver before use.
(function() {
    'use strict';

    const TunData = {
        resolve: null,

        // Action services (POST only): TunCtl carries operator commands to
        // the registry, TunIssue creates tokens and certificates.
        CTL_ENDPOINT: '/42/TunCtl',
        ISSUE_ENDPOINT: '/40/TunIssue',

        headers: function() {
            const token = sessionStorage.getItem('bearerToken') || localStorage.getItem('bearerToken');
            return { 'Authorization': token ? 'Bearer ' + token : '', 'Content-Type': 'application/json' };
        },

        // request sends a JSON body and returns the parsed response; a
        // failure throws with the server's message.
        request: async function(method, endpoint, body) {
            const resp = await fetch(TunData.resolve(endpoint), {
                method: method, headers: TunData.headers(), body: body === undefined ? undefined : JSON.stringify(body)
            });
            const text = await resp.text();
            if (!resp.ok) throw new Error(text || ('HTTP ' + resp.status));
            return text ? JSON.parse(text) : {};
        },

        // list returns every row of a table. L8QL computes totals only on
        // page 0, so the query asks for page 0 with a limit of 500 (L8QL
        // refuses 1000 and more).
        list: async function(endpoint, model, where) {
            const text = 'select * from ' + model + (where ? ' where ' + where : '') + ' limit 500 page 0';
            const resp = await fetch(TunData.resolve(endpoint) + '?body=' + encodeURIComponent(JSON.stringify({ text: text })),
                { method: 'GET', headers: TunData.headers() });
            if (!resp.ok) throw new Error(model + ': HTTP ' + resp.status);
            const data = await resp.json();
            return data.list || [];
        },

        // liveEdges are the real edges that reported in the last two
        // minutes (an edge reports every 5 s).
        liveEdges: function(nodes) {
            const since = Date.now() / 1000 - 120;
            return nodes.filter(n => !n.simulated && Number(n.lastSeen || 0) >= since);
        },

        currentUser: function() {
            return sessionStorage.getItem('currentUser') || '';
        }
    };

    window.TunData = TunData;
})();
