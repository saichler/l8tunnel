// Mobile app shell: auth, config, the sidebar and section loading.
// Adapted from l8secure-scan's (itself from l8erp's): one section,
// 'dashboard', which hosts the KPIs and the Layer8MNav views.
(function() {
    'use strict';

    const SECTIONS = { 'dashboard': 'sections/dashboard.html' };
    let currentSection = 'dashboard';

    // loadPermissions sets the per-type action permissions the nav
    // follows. A failure throws: an unset Layer8DPermissions reads as
    // permissive, which would offer actions the user isn't entitled to.
    async function loadPermissions() {
        const token = sessionStorage.getItem('bearerToken') || localStorage.getItem('bearerToken');
        const resp = await fetch('/permissions', {
            headers: { 'Authorization': 'Bearer ' + token, 'Content-Type': 'application/json' }
        });
        if (resp.status === 401) {
            Layer8MAuth.logout();
            throw new Error('/permissions: the session expired');
        }
        if (!resp.ok) throw new Error('/permissions returned HTTP ' + resp.status);
        const perms = await resp.json();
        if (perms === null || typeof perms !== 'object') throw new Error('/permissions: expected an object');
        window.Layer8DPermissions = perms;
    }

    window.MobileApp = {
        async init() {
            if (!Layer8MAuth.requireAuth()) return;
            await Layer8MConfig.load();
            const logo = Layer8MConfig.getLogo();
            Layer8DLogo.register(document.getElementById('app-favicon'), logo, 'href');
            Layer8DLogo.register(document.getElementById('app-header-logo'), logo, 'src');
            Layer8DLogo.register(document.getElementById('app-sidebar-logo'), logo, 'src');

            TunData.resolve = Layer8MConfig.resolveEndpoint.bind(Layer8MConfig);
            await loadPermissions();
            Layer8DWebSocket.init();
            TunKeyDownload.hide();
            this.updateUserInfo();

            // l8tunnel has no ModConfig service (ModconfigFailureNoLogout).
            Layer8DModuleFilter._loaded = true;

            this.initSidebar();
            document.getElementById('refresh-btn').addEventListener('click', () => this.loadSection(currentSection));
            await this.loadSection('dashboard');
        },

        updateUserInfo() {
            const username = Layer8MAuth.getUsername();
            document.getElementById('user-name').textContent = username;
            document.getElementById('user-avatar').textContent = username.charAt(0).toUpperCase();
        },

        initSidebar() {
            document.getElementById('sidebar-overlay').addEventListener('click', () => this.closeSidebar());
            document.getElementById('menu-toggle').addEventListener('click', () => this.openSidebar());
            document.querySelectorAll('.sidebar-item[data-section]').forEach(item => {
                item.addEventListener('click', async (e) => {
                    e.preventDefault();
                    this.closeSidebar();
                    await this.loadSection(item.dataset.section);
                    if (item.dataset.module) Layer8MNav.navigateToModule(item.dataset.module);
                    this.updateNavState(item);
                });
            });
        },

        openSidebar() {
            document.getElementById('sidebar').classList.add('open');
            document.getElementById('sidebar-overlay').classList.add('visible');
            document.body.style.overflow = 'hidden';
        },

        closeSidebar() {
            document.getElementById('sidebar').classList.remove('open');
            document.getElementById('sidebar-overlay').classList.remove('visible');
            document.body.style.overflow = '';
        },

        async loadSection(section) {
            const contentArea = document.getElementById('content-area');
            contentArea.style.opacity = '0.5';
            try {
                const response = await fetch(SECTIONS[section] + '?t=' + Date.now());
                if (!response.ok) throw new Error('HTTP ' + response.status);
                contentArea.innerHTML = await response.text();
                initTunMobileDashboard();
                currentSection = section;
                contentArea.scrollTop = 0;
            } catch (error) {
                console.error('Error loading section:', error);
                contentArea.innerHTML = '<div class="nav-empty-state"><h3>Failed to load</h3><p>' +
                    Layer8DUtils.escapeHtml(error.message) + '</p></div>';
            }
            contentArea.style.opacity = '1';
        },

        updateNavState(active) {
            document.querySelectorAll('.sidebar-item').forEach(item => item.classList.toggle('active', item === active));
        },

        logout() {
            Layer8MAuth.logout();
        }
    };

    document.addEventListener('DOMContentLoaded', () => MobileApp.init());
})();
