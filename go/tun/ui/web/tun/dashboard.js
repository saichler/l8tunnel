// The desktop dashboard: KPI widgets (numbers from tun-dashboard-core.js),
// refreshed when a live table changes.
(function() {
    'use strict';

    const esc = Layer8DUtils.escapeHtml;
    let unsubscribe = [];
    let pending = null;

    const ICON = (body) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + body + '</svg>';

    function go(section) {
        document.querySelectorAll('.nav-link').forEach(l => l.classList.toggle('active', l.dataset.section === section));
        loadSection(section);
    }

    async function render() {
        const grid = document.getElementById('tun-dashboard-kpis');
        if (!grid) return false;
        let k;
        try {
            k = await TunDashboardCore.load();
        } catch (e) {
            grid.innerHTML = '<div class="tun-muted">Dashboard data unavailable: ' + esc(e.message) + '</div>';
            return true;
        }
        const w = (label, icon, section, value, opts) =>
            Layer8DWidget.render({ label: label, iconSvg: ICON(icon), onClick: "TunDashboard.go('" + section + "')" }, value, opts);
        grid.innerHTML = [
            w('Ready relays', '<rect x="3" y="4" width="18" height="6" rx="1"/><rect x="3" y="14" width="18" height="6" rx="1"/>',
                'tunnels', k.readyRelays + ' / ' + k.relays, {}),
            w('Agents online', '<rect x="2" y="4" width="20" height="13" rx="2"/><path d="M8 21h8M12 17v4"/>', 'tunnels', k.online, {}),
            w('Agents offline (24 h)', '<circle cx="12" cy="12" r="10"/><path d="M4.9 4.9l14.2 14.2"/>', 'tunnels', k.offline24h, {}),
            w('Tunnels', '<path d="M5 12h14M13 6l6 6-6 6"/>', 'tunnels', k.tunnels, { subtitle: esc(TunDashboardCore.typesText(k)) }),
            w('Unhealthy backends', '<path d="M12 9v4M12 17h.01"/><path d="M10.3 3.9 1.8 18a2 2 0 0 0 1.7 3h17a2 2 0 0 0 1.7-3L13.7 3.9a2 2 0 0 0-3.4 0z"/>',
                'edge', k.unhealthy, {}),
            w('Days to certificate expiry', '<path d="M12 2l8 4v6c0 5-3.5 8.5-8 10-4.5-1.5-8-5-8-10V6z"/>', 'edge',
                k.certDays === null ? '-' : String(k.certDays), {})
        ].join('');
        return true;
    }

    // refreshSoon coalesces bursts of live-table changes.
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

    window.initializeTunDashboard = function() {
        stop();
        document.getElementById('tun-dashboard-hero').innerHTML = Layer8SectionGenerator.renderHero({
            title: 'Dashboard', subtitle: 'Relays, agents, tunnels and the edge at a glance', icon: TunIcons.tunnels
        });
        render();
        TunDashboardCore.LIVE_MODELS.forEach(m => unsubscribe.push(Layer8DWebSocket.subscribe(m, refreshSoon)));
    };

    window.TunDashboard = { go: go };
})();
