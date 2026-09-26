// Creates the l8tunnel modules (one per generated section) and installs
// the l8tunnel actions on them.
(function() {
    'use strict';

    const sectionModule = (key, service, init, namespaces) => Layer8DModuleFactory.create({
        namespace: 'Tun', defaultModule: key, defaultService: service, sectionSelector: key,
        initializerName: init, requiredNamespaces: namespaces
    });

    window.initializeTunModules = function() {
        sectionModule('tunnels', 'agents', 'initializeTunTunnelsModule', ['TunLive']);
        sectionModule('access', 'tokens', 'initializeTunAccessModule', ['TunAccess']);
        sectionModule('edge', 'domains', 'initializeTunEdgeModule', ['TunEdge']);
        sectionModule('alerts', 'rules', 'initializeTunAlertsModule', ['TunAlerts']);

        // Layer8DModuleFactory.create() re-attaches the CRUD and navigation
        // handlers on every call, so the actions wrap them after the last.
        TunActions.install();

        const origLoad = Tun.loadServiceView;
        Tun.loadServiceView = function(moduleKey, serviceKey) {
            origLoad.call(Tun, moduleKey, serviceKey);
            if (serviceKey === 'routerports') TunRouterPorts.render('edge-routerports-table-container');
        };
    };

    // The section initializers load what the badges compare against, then
    // show the section.
    window.initializeTunTunnels = async function() {
        try {
            const versions = (await TunData.list('/42/TunRelay', 'TunRelay')).filter(r => !r.simulated).map(r => r.version);
            TunLive.relayVersion = versions.reduce((a, b) => (TunLive.compareVersions(b, a) > 0 ? b : a), versions[0] || '');
        } catch (e) {
            console.error('relay versions:', e);
        }
        initializeTunTunnelsModule();
    };
    window.initializeTunAccess = () => initializeTunAccessModule();
    window.initializeTunEdge = async function() {
        try {
            const nodes = TunData.liveEdges(await TunData.list('/41/EdgeNode', 'EdgeNode'));
            TunEdge.appliedVersion = nodes.length ? Math.min(...nodes.map(n => Number(n.configVersion || 0))) : null;
        } catch (e) {
            console.error('edge config versions:', e);
        }
        initializeTunEdgeModule();
    };
    window.initializeTunAlerts = () => initializeTunAlertsModule();
})();
