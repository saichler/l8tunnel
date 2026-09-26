// The mobile dashboard: the same KPIs as desktop (tun-dashboard-core.js)
// as stat cards, above the Layer8MNav home.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;
    let unsubscribe = [];
    let pending = null;

    async function render() {
        const grid = document.getElementById('tun-m-kpis');
        if (!grid) return false;
        let k;
        try {
            k = await TunDashboardCore.load();
        } catch (e) {
            grid.innerHTML = '<div class="tun-muted">Dashboard data unavailable: ' + esc(e.message) + '</div>';
            return true;
        }
        const card = (value, label, sub) => '<div class="nav-stat-card"><div class="nav-stat-content">' +
            '<div class="nav-stat-value">' + esc(String(value)) + '</div>' +
            '<div class="nav-stat-label">' + esc(label) + '</div>' +
            (sub ? '<div class="tun-muted">' + esc(sub) + '</div>' : '') + '</div></div>';
        grid.innerHTML = [
            card(k.readyRelays + ' / ' + k.relays, 'Ready relays'),
            card(k.online, 'Agents online'),
            card(k.offline24h, 'Agents offline (24 h)'),
            card(k.tunnels, 'Tunnels', TunDashboardCore.typesText(k)),
            card(k.unhealthy, 'Unhealthy backends'),
            card(k.certDays === null ? '-' : k.certDays, 'Days to certificate expiry')
        ].join('');
        return true;
    }

    function refreshSoon() {
        if (pending) return;
        pending = setTimeout(async () => {
            pending = null;
            if (!(await render())) stop();
        }, 1000);
    }

    function stop() {
        unsubscribe.forEach(u => u());
        unsubscribe = [];
    }

    window.initTunMobileDashboard = function() {
        stop();
        render();
        Layer8MNav.showHome();
        TunDashboardCore.LIVE_MODELS.forEach(m => unsubscribe.push(Layer8DWebSocket.subscribe(m, refreshSoon)));
    };
})();
