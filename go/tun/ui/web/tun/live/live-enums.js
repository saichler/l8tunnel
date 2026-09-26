// Enums and renderers of the live tables (TunAgent, TunLiveTunnel,
// TunRelay, EdgeNode). Values match proto/tun.proto.
(function() {
    'use strict';

    window.TunLive = window.TunLive || {};
    const factory = Layer8EnumFactory;
    const { createStatusRenderer, renderEnum, renderFileSize } = Layer8DRenderers;

    const RELAY_STATE = factory.create([
        ['Unspecified', null, ''],
        ['Ready', 'ready', 'layer8d-status-active'],
        ['Draining', 'draining', 'layer8d-status-pending'],
        ['Down', 'down', 'layer8d-status-terminated']
    ]);
    const AGENT_STATE = factory.create([
        ['Unspecified', null, ''],
        ['Online', 'online', 'layer8d-status-active'],
        ['Grace', 'grace', 'layer8d-status-pending'],
        ['Offline', 'offline', 'layer8d-status-inactive']
    ]);
    const LIVE_STATE = factory.create([
        ['Unspecified', null, ''],
        ['Active', 'active', 'layer8d-status-active'],
        ['Grace', 'grace', 'layer8d-status-pending']
    ]);
    const TUNNEL_TYPE = factory.withValues([
        ['Unspecified', null], ['TCP', 'tcp'], ['SSH', 'ssh'], ['HTTP', 'http'], ['TLS', 'tls']
    ]);
    const TRANSPORT = factory.withValues([
        ['Unspecified', null], ['TLS', 'tls'], ['WebSocket', 'websocket'], ['WebSocket via proxy', 'proxy']
    ]);
    const DISCONNECT_REASON = factory.simple([
        'Unspecified', 'Heartbeat timeout', 'Token revoked', 'Relay drained', 'Relay lost',
        'Taken over', 'Agent closed', 'Operator'
    ]);

    TunLive.enums = {
        RELAY_STATE: RELAY_STATE.enum, RELAY_STATE_VALUES: RELAY_STATE.values, RELAY_STATE_CLASSES: RELAY_STATE.classes,
        AGENT_STATE: AGENT_STATE.enum, AGENT_STATE_VALUES: AGENT_STATE.values, AGENT_STATE_CLASSES: AGENT_STATE.classes,
        LIVE_STATE: LIVE_STATE.enum, LIVE_STATE_VALUES: LIVE_STATE.values, LIVE_STATE_CLASSES: LIVE_STATE.classes,
        TUNNEL_TYPE: TUNNEL_TYPE.enum, TUNNEL_TYPE_VALUES: TUNNEL_TYPE.values,
        TRANSPORT: TRANSPORT.enum, TRANSPORT_VALUES: TRANSPORT.values,
        DISCONNECT_REASON: DISCONNECT_REASON.enum
    };

    TunLive.render = {
        relayState: createStatusRenderer(RELAY_STATE.enum, RELAY_STATE.classes),
        agentState: createStatusRenderer(AGENT_STATE.enum, AGENT_STATE.classes),
        liveState: createStatusRenderer(LIVE_STATE.enum, LIVE_STATE.classes),
        tunnelType: (v) => renderEnum(v, TUNNEL_TYPE.enum),
        transport: (v) => renderEnum(v, TRANSPORT.enum),
        disconnectReason: (v) => renderEnum(v, DISCONNECT_REASON.enum),
        // int64 counters arrive as strings
        bytes: (v) => renderFileSize(Number(v || 0)),
        // A timestamp, or '-' when it was never set (renderDateTime shows 0
        // as "Current").
        when: (v) => Number(v || 0) ? Layer8DRenderers.renderDateTime(v) : '-',
        day: (v) => Number(v || 0) ? Layer8DRenderers.renderDate(v) : '-',
        // heartbeat round trip, in microseconds
        rtt: (v) => { const us = Number(v || 0); return us ? (us / 1000).toFixed(1) + ' ms' : '-'; }
    };
})();
