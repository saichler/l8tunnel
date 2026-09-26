// Detail forms of the live tables. Every field is display-only: the
// registry and the edge write these records.
(function() {
    'use strict';

    const f = Layer8FormFactory;
    const ro = TunForms.readOnly;
    const e = TunLive.enums;

    TunLive.forms = {
        TunAgent: f.form('Agent', [
            f.section('Agent', ro([
                ...f.text('agentId', 'Agent ID'),
                ...f.select('state', 'State', e.AGENT_STATE),
                ...f.text('tokenName', 'Token'),
                ...f.text('tokenId', 'Token ID'),
                ...f.text('certSerial', 'Certificate serial'),
                ...f.text('version', 'Version'),
                ...f.text('os', 'OS'),
                ...f.text('arch', 'Architecture')
            ])),
            f.section('Connection', ro([
                ...f.text('publicIp', 'Public IP'),
                ...f.text('relayId', 'Relay'),
                ...f.select('transport', 'Transport', e.TRANSPORT),
                ...f.text('sessionId', 'Session'),
                ...f.datetime('connectedAt', 'Connected'),
                ...f.datetime('lastHeartbeat', 'Last heartbeat'),
                ...f.number('rttUs', 'Heartbeat RTT (µs)'),
                ...f.datetime('graceUntil', 'Grace until'),
                ...f.datetime('lastSeen', 'Last seen'),
                ...f.select('disconnectReason', 'Disconnect reason', e.DISCONNECT_REASON)
            ])),
            f.section('Traffic', ro([
                ...f.number('tunnelCount', 'Tunnels'),
                ...f.number('activeStreams', 'Active streams'),
                ...f.number('bytesIn', 'Bytes in'),
                ...f.number('bytesOut', 'Bytes out'),
                ...f.checkbox('simulated', 'Simulated')
            ]))
        ]),
        TunLiveTunnel: f.form('Live tunnel', [
            f.section('Tunnel', ro([
                ...f.text('name', 'Name'),
                ...f.text('tunnelId', 'Tunnel ID'),
                ...f.select('type', 'Type', e.TUNNEL_TYPE),
                ...f.select('state', 'State', e.LIVE_STATE),
                ...f.text('hostname', 'Hostname'),
                ...f.tags('domains', 'Custom domains'),
                ...f.number('publicPort', 'Public port'),
                ...f.checkbox('accessToken', 'Access token required')
            ])),
            f.section('Where', ro([
                ...f.text('relayId', 'Relay'),
                ...f.text('agentId', 'Agent'),
                ...f.text('tokenId', 'Token ID'),
                ...f.text('sessionId', 'Session'),
                ...f.datetime('connectedAt', 'Connected'),
                ...f.datetime('graceUntil', 'Grace until')
            ])),
            f.section('Traffic', ro([
                ...f.number('activeConns', 'Active connections'),
                ...f.number('totalConns', 'Total connections'),
                ...f.number('bytesIn', 'Bytes in'),
                ...f.number('bytesOut', 'Bytes out'),
                ...f.checkbox('simulated', 'Simulated')
            ]))
        ]),
        TunRelay: f.form('Relay', [
            f.section('Relay', ro([
                ...f.text('relayId', 'Relay'),
                ...f.select('state', 'State', e.RELAY_STATE),
                ...f.text('podIp', 'Pod IP'),
                ...f.text('version', 'Version'),
                ...f.datetime('startedAt', 'Started'),
                ...f.datetime('lastSeen', 'Last seen'),
                ...f.date('certNotAfter', 'Certificate expires'),
                ...f.checkbox('simulated', 'Simulated')
            ])),
            f.section('Ports', ro([
                ...f.number('tlsPort', 'TLS'),
                ...f.number('httpPort', 'HTTP'),
                ...f.number('streamPort', 'Stream'),
                ...f.number('gatewayPort', 'SSH gateway'),
                ...f.number('opsPort', 'Ops')
            ])),
            f.section('Load', ro([
                ...f.number('sessions', 'Agents'),
                ...f.number('tunnels', 'Tunnels'),
                ...f.number('bytesIn', 'Bytes in'),
                ...f.number('bytesOut', 'Bytes out')
            ]))
        ]),
        EdgeNode: f.form('Edge node', [
            f.section('Edge', ro([
                ...f.text('edgeId', 'Edge'),
                ...f.text('nodeIp', 'Node IP'),
                ...f.text('version', 'Version'),
                ...f.number('configVersion', 'Config version'),
                ...f.datetime('startedAt', 'Started'),
                ...f.datetime('lastSeen', 'Last seen'),
                ...f.number('activeConns', 'Active connections'),
                ...f.number('totalConns', 'Total connections'),
                ...f.number('bytesIn', 'Bytes in'),
                ...f.number('bytesOut', 'Bytes out'),
                ...f.checkbox('simulated', 'Simulated')
            ])),
            f.section('Listeners', ro([
                ...f.inlineTable('listeners', 'Listeners', [
                    { key: 'port', label: 'Port', type: 'number' },
                    { key: 'portEnd', label: 'To', type: 'number' },
                    { key: 'protocol', label: 'Protocol', type: 'select', options: TunEdge.enums.PROTOCOL },
                    { key: 'bound', label: 'Bound', type: 'checkbox' },
                    { key: 'error', label: 'Error', type: 'text' },
                    { key: 'domains', label: 'Domains', type: 'tags' }
                ])
            ])),
            f.section('Backends', ro([
                ...f.inlineTable('backends', 'Backends', [
                    { key: 'domain', label: 'Forward', type: 'text' },
                    { key: 'listenPort', label: 'Port', type: 'number' },
                    { key: 'target', label: 'Target', type: 'text' },
                    { key: 'healthy', label: 'Healthy', type: 'checkbox' },
                    { key: 'activeConns', label: 'Active', type: 'number' },
                    { key: 'lastError', label: 'Last error', type: 'text' },
                    { key: 'lastCheck', label: 'Checked', type: 'datetime' }
                ])
            ]))
        ])
    };
})();
