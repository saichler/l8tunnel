// Main application initialization for the l8tunnel management UI.

// Get authentication headers with bearer token
function getAuthHeaders() {
    const bearerToken = sessionStorage.getItem('bearerToken');
    return {
        'Authorization': bearerToken ? `Bearer ${bearerToken}` : '',
        'Content-Type': 'application/json'
    };
}

// makeAuthenticatedRequest is the shell's authenticated fetch; l8ui's SYS
// modules (L8Logs) call it.
async function makeAuthenticatedRequest(url, options = {}) {
    const bearerToken = sessionStorage.getItem('bearerToken');
    if (!bearerToken) {
        window.location.href = 'l8ui/login/index.html';
        return;
    }
    const response = await fetch(url, {
        ...options,
        headers: { 'Authorization': `Bearer ${bearerToken}`, 'Content-Type': 'application/json', ...options.headers }
    });
    if (response.status === 401) {
        sessionStorage.removeItem('bearerToken');
        window.location.href = 'l8ui/login/index.html';
        return;
    }
    return response;
}

// Logout function
function logout() {
    sessionStorage.removeItem('bearerToken');
    localStorage.removeItem('bearerToken');
    localStorage.removeItem('rememberedUser');
    window.location.href = 'l8ui/login/index.html';
}

// loadPermissions sets the per-type action permissions the tables and
// forms follow. A failure throws: an unset Layer8DPermissions reads as
// permissive, which would offer actions the user isn't entitled to.
async function loadPermissions(bearerToken) {
    const resp = await fetch('/permissions', {
        headers: { 'Authorization': `Bearer ${bearerToken}`, 'Content-Type': 'application/json' }
    });
    if (resp.status === 401) {
        logout();
        throw new Error('/permissions: the session expired');
    }
    if (!resp.ok) throw new Error('/permissions returned HTTP ' + resp.status);
    const perms = await resp.json();
    if (perms === null || typeof perms !== 'object') throw new Error('/permissions: expected an object');
    window.Layer8DPermissions = perms;
}

document.addEventListener('DOMContentLoaded', async function() {
    // The theme is an attribute on <html>, which doesn't survive the
    // navigation from the login page, so apply it here, before the logo
    // (Layer8DLogo reads the active theme's colors).
    Layer8DThemeSwitcher.init();

    await Layer8DConfig.load();
    const logo = Layer8DConfig.getLogo();
    Layer8DLogo.register(document.getElementById('app-favicon'), logo, 'href');
    Layer8DLogo.register(document.getElementById('app-header-logo'), logo, 'src');

    const bearerToken = sessionStorage.getItem('bearerToken');
    if (!bearerToken) {
        window.location.href = 'l8ui/login/index.html';
        return;
    }
    // Sync the bearer token to localStorage so iframes can use it.
    localStorage.setItem('bearerToken', bearerToken);
    window.bearerToken = bearerToken;

    await loadPermissions(bearerToken);

    // Realtime tables (agents, live tunnels, relays) subscribe through it.
    Layer8DWebSocket.init();

    document.querySelector('.username').textContent = sessionStorage.getItem('currentUser') || 'User';

    // l8tunnel has no ModConfig service (ModconfigFailureNoLogout): mark
    // the module filter loaded so it enables every module.
    Layer8DModuleFilter._loaded = true;

    const navLinks = document.querySelectorAll('.nav-link');
    navLinks.forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            navLinks.forEach(l => l.classList.remove('active'));
            this.classList.add('active');
            loadSection(this.getAttribute('data-section'));
        });
    });

    initializeTunModules();
    loadSection('dashboard');
});
