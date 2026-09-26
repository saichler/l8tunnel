// Section navigation and loading: one top-level section per sidebar item.

const sections = {
    dashboard: 'sections/dashboard.html',
    tunnels: 'sections/tunnels.html',
    access: 'sections/access.html',
    edge: 'sections/edge.html',
    alerts: 'sections/alerts.html',
    system: 'sections/system.html'
};

// Section initializers (defined by tun-init.js, dashboard.js and l8sys).
const sectionInitializers = {
    dashboard: () => initializeTunDashboard(),
    tunnels: () => initializeTunTunnels(),
    access: () => initializeTunAccess(),
    edge: () => initializeTunEdge(),
    alerts: () => initializeTunAlerts(),
    system: () => initializeL8Sys()
};

// Load section content dynamically
function loadSection(sectionName) {
    const contentArea = document.getElementById('content-area');
    const sectionFile = sections[sectionName];

    if (!sectionFile) {
        contentArea.innerHTML = '<div class="section-container"><h2 class="section-title">Error</h2><div class="section-content">Section not found.</div></div>';
        return;
    }

    contentArea.style.opacity = '0';
    contentArea.style.transform = 'translateY(20px)';

    fetch(sectionFile + '?t=' + new Date().getTime())
        .then(response => {
            if (!response.ok) {
                throw new Error('Section not found');
            }
            return response.text();
        })
        .then(html => {
            setTimeout(() => {
                contentArea.innerHTML = html;

                const placeholder = contentArea.querySelector('[id$="-section-placeholder"]');
                if (placeholder) {
                    const temp = document.createElement('div');
                    temp.innerHTML = Layer8SectionGenerator.generate(sectionName);
                    placeholder.replaceWith(...temp.children);
                }

                setTimeout(() => {
                    contentArea.style.transition = 'opacity 0.5s ease, transform 0.5s ease';
                    contentArea.style.opacity = '1';
                    contentArea.style.transform = 'translateY(0)';
                }, 50);

                const sectionContainer = contentArea.querySelector('.section-container');
                if (sectionContainer) {
                    sectionContainer.style.animation = 'fade-in-up 0.6s ease-out';
                }

                sectionInitializers[sectionName]();
                Layer8DModuleFilter.applyToSection(sectionName);
            }, 200);
        })
        .catch(error => {
            console.error('Error loading section:', error);
            contentArea.innerHTML = '<div class="section-container"><h2 class="section-title">Error</h2><div class="section-content">Failed to load section content.</div></div>';
            contentArea.style.opacity = '1';
            contentArea.style.transform = 'translateY(0)';
        });
}
