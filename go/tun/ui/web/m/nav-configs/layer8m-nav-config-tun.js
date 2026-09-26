// The l8tunnel mobile navigation: the same sections and services as the
// desktop sidebar. Read-only services open TunMobile.details for their
// actions; tokens are issued and revoked through TunIssue; the TUNNEL_BASE
// domain opens its read-only-names form and can't be deleted.
(function() {
    'use strict';

    window.LAYER8M_NAV_CONFIG = window.LAYER8M_NAV_CONFIG || {};

    const details = (key) => (item) => TunMobile.details(svc(key), item);
    const all = {};
    // s declares a service and remembers it for details().
    function s(key, label, endpoint, model, idField, extra) {
        all[key] = Object.assign({ key: key, label: label, icon: key, endpoint: endpoint, model: model, idField: idField }, extra || {});
        return all[key];
    }
    const svc = (key) => all[key];
    const live = (key, label, endpoint, model, idField, sort) =>
        s(key, label, endpoint, model, idField, { readOnly: true, realtime: true, defaultSort: sort, onRowClick: details(key) });

    // The home screen is the dashboard (its KPIs sit above these cards), so
    // there's no Dashboard module card.
    LAYER8M_NAV_CONFIG.modules = [
        { key: 'tunnels', label: 'Tunnels', icon: 'tunnels', hasSubModules: true },
        { key: 'access', label: 'Access', icon: 'access', hasSubModules: true },
        { key: 'edge', label: 'Edge', icon: 'edge', hasSubModules: true },
        { key: 'alerts', label: 'Alerts', icon: 'alerts', hasSubModules: true },
        { key: 'system', label: 'System', icon: 'system', hasSubModules: true }
    ];

    LAYER8M_NAV_CONFIG.tunnels = {
        subModules: [{ key: 'tunnels', label: 'Tunnels', icon: 'tunnels' }],
        services: {
            tunnels: [
                live('agents', 'Agents', '/42/TunAgent', 'TunAgent', 'agentId', { column: 'state', direction: 'asc' }),
                live('live', 'Live', '/42/TunLive', 'TunLiveTunnel', 'name', { column: 'name', direction: 'asc' }),
                live('relays', 'Relays', '/42/TunRelay', 'TunRelay', 'relayId', { column: 'relayId', direction: 'asc' }),
                live('edgenodes', 'Edge nodes', '/41/EdgeNode', 'EdgeNode', 'edgeId', { column: 'edgeId', direction: 'asc' })
            ]
        }
    };

    LAYER8M_NAV_CONFIG.access = {
        subModules: [{ key: 'access', label: 'Access', icon: 'access' }],
        services: {
            access: [
                s('tokens', 'Tokens', '/40/TunToken', 'TunToken', 'tokenId', {
                    onRowClick: details('tokens'),
                    onAdd: () => TunMobile.issueToken(),
                    onDelete: (id) => TunMobile.revokeToken(id)
                }),
                s('reservations', 'Reservations', '/40/TunResv', 'TunReservation', 'reservationId'),
                s('gwkeys', 'Gateway keys', '/40/TunGwKey', 'TunGatewayKey', 'keyId'),
                s('agentcerts', 'Agent certificates', '/40/TunAgCert', 'TunAgentCert', 'certId', {
                    readOnly: true, onRowClick: details('agentcerts')
                })
            ]
        }
    };

    LAYER8M_NAV_CONFIG.edge = {
        subModules: [{ key: 'edge', label: 'Edge', icon: 'edge' }],
        services: {
            edge: [
                s('domains', 'Domains', '/41/EdgeDomain', 'EdgeDomain', 'domainId', {
                    onRowClick: details('domains'),
                    onEdit: (id, item) => TunMobile.editDomain(id, item),
                    onDelete: (id, item) => TunMobile.deleteDomain(id, item)
                }),
                s('routerports', 'Router ports', '/41/EdgeNode', 'EdgeNode', 'edgeId', {
                    customInit: 'TunRouterPortsM', customContainer: 'tun-m-router-ports',
                    subtitle: 'The public ports the edges listen on: forward these on the router'
                })
            ]
        }
    };

    LAYER8M_NAV_CONFIG.alerts = {
        subModules: [{ key: 'alerts', label: 'Alerts', icon: 'alerts' }],
        services: {
            alerts: [
                s('rules', 'Rules', '/43/TunAlert', 'TunAlertRule', 'ruleId'),
                s('deliveries', 'Delivery log', '/78/Notify', 'NotifyRecord', 'notifyId', {
                    readOnly: true, defaultSort: { column: 'requestedAt', direction: 'desc' }, onRowClick: details('deliveries')
                }),
                s('integrations', 'Integrations', '/78/IntegCfg', 'IntegrationConfig', 'integrationId')
            ]
        }
    };

    LAYER8M_NAV_CONFIG.system = {
        subModules: [
            { key: 'health', label: 'Health', icon: 'health' },
            { key: 'security', label: 'Security', icon: 'security' }
        ],
        services: {
            health: [
                s('health-monitor', 'Health Monitor', '/0/Health', 'L8Health', 'service', { readOnly: true })
            ],
            security: [
                s('users', 'Users', '/73/users', 'L8User', 'userId'),
                s('roles', 'Roles', '/74/roles', 'L8Role', 'roleId'),
                s('credentials', 'Credentials', '/75/Creds', 'L8Credentials', 'id'),
                s('events', 'Events', '/76/Events', 'EventRecord', 'eventId', {
                    readOnly: true, defaultSort: { column: 'occurredAt', direction: 'desc' }, onRowClick: details('events')
                })
            ]
        }
    };

    const icon = (body) => '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">' + body + '</svg>';
    LAYER8M_NAV_CONFIG.icons = Object.assign({}, TunIcons, {
        dashboard: icon('<path d="M3 3v18h18"/><path d="M18 17V9M13 17V5M8 17v-3"/>'),
        system: icon('<circle cx="12" cy="12" r="3"/><path d="M12 1v4M12 19v4M4.2 4.2l2.8 2.8M17 17l2.8 2.8M1 12h4M19 12h4M4.2 19.8 7 17M17 7l2.8-2.8"/>'),
        health: icon('<path d="M22 12h-4l-3 8-4-16-3 8H2"/>'),
        security: icon('<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10Z"/>'),
        'health-monitor': icon('<path d="M22 12h-4l-3 8-4-16-3 8H2"/>'),
        back: '&#x2190;',
        default: icon('<path d="M14 2H6a2 2 0 0 0-2 2v16a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V8Z"/><path d="M14 2v6h6"/>')
    });
    LAYER8M_NAV_CONFIG.getIcon = function(key) {
        return this.icons[key] || this.icons['default'];
    };
})();
