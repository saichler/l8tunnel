// The l8tunnel module configuration: one module per generated section.
(function() {
    'use strict';

    const svc = Layer8ModuleConfigFactory.service;
    const mod = Layer8ModuleConfigFactory.module;

    // The live tables are written only by the registry and the edge, so
    // they're read-only here (ImmutabilityUiAlignment); operators act on
    // them through the detail popups' actions.
    const live = (key, label, endpoint, model, sort) => Object.assign(
        svc(key, label, key, endpoint, model),
        { readOnly: true, realtime: true, defaultSort: sort });

    const agentCerts = svc('agentcerts', 'Agent certificates', 'agentcerts', '/40/TunAgCert', 'TunAgentCert');
    // A certificate record is immutable apart from revocation, which is an
    // action on its detail popup; new ones are issued, not added.
    agentCerts.readOnly = true;

    const deliveries = svc('deliveries', 'Delivery log', 'deliveries', '/78/Notify', 'NotifyRecord');
    deliveries.readOnly = true; // NotifyRecord is immutable (PUT is refused)
    deliveries.defaultSort = { column: 'requestedAt', direction: 'desc' };

    const routerPorts = svc('routerports', 'Router ports', 'routerports', '/41/EdgeNode', 'EdgeNode');
    routerPorts.customView = true; // one row per listener, across every edge (router-ports.js)

    Layer8ModuleConfigFactory.create({
        namespace: 'Tun',
        modules: {
            'tunnels': mod('Tunnels', 'tunnels', [
                live('agents', 'Agents', '/42/TunAgent', 'TunAgent', { column: 'state', direction: 'asc' }),
                live('live', 'Live', '/42/TunLive', 'TunLiveTunnel', { column: 'name', direction: 'asc' }),
                live('relays', 'Relays', '/42/TunRelay', 'TunRelay', { column: 'relayId', direction: 'asc' }),
                live('edgenodes', 'Edge nodes', '/41/EdgeNode', 'EdgeNode', { column: 'edgeId', direction: 'asc' })
            ]),
            'access': mod('Access', 'access', [
                svc('tokens', 'Tokens', 'tokens', '/40/TunToken', 'TunToken'),
                svc('reservations', 'Reservations', 'reservations', '/40/TunResv', 'TunReservation'),
                svc('gwkeys', 'Gateway keys', 'gwkeys', '/40/TunGwKey', 'TunGatewayKey'),
                agentCerts
            ]),
            'edge': mod('Edge', 'edge', [
                svc('domains', 'Domains', 'domains', '/41/EdgeDomain', 'EdgeDomain'),
                routerPorts
            ]),
            'alerts': mod('Alerts', 'alerts', [
                svc('rules', 'Rules', 'rules', '/43/TunAlert', 'TunAlertRule'),
                deliveries,
                svc('integrations', 'Integrations', 'integrations', '/78/IntegCfg', 'IntegrationConfig')
            ])
        },
        submodules: ['TunLive', 'TunAccess', 'TunEdge', 'TunAlerts']
    });
})();
