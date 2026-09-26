// The actions on l8tunnel records, shared by both shells: operator
// commands on the live tables (disconnect, drain, resume), certificate
// revocation and links to related records. Each action is a spec the
// shell renders as a button: { label, danger, confirm, run } where run
// performs it and returns the success message, or { label, open } that
// opens a related record, or { label, invoke } that the shell handles
// (issueCert, connect).
(function() {
    'use strict';

    const CTL = { DRAIN: 2, RESUME: 3, DISCONNECT_AGENT: 4, DISCONNECT_TUNNEL: 5 };

    function command(label, confirm, cmd) {
        return {
            label: label, danger: true, confirm: confirm,
            run: async () => {
                await TunData.request('POST', TunData.CTL_ENDPOINT, Object.assign({ requestedBy: TunData.currentUser() }, cmd));
                return label + ': done';
            }
        };
    }

    const open = (label, serviceKey, id) => ({ label: label, open: { service: serviceKey, id: id } });

    const byModel = {
        TunAgent: (d) => {
            const b = [];
            if (Number(d.state) === 1) {
                b.push(command('Disconnect agent', 'Disconnect agent ' + d.agentId +
                    '? Every tunnel of the session closes; the agent reconnects on its own.',
                    { kind: CTL.DISCONNECT_AGENT, agentId: d.agentId }));
            }
            if (d.tokenId) b.push(open('Open token', 'tokens', d.tokenId));
            return b;
        },
        TunLiveTunnel: (d) => {
            const b = [];
            if (TunConnect.supports(d)) b.push({ label: 'Connect', invoke: 'connect', record: d });
            if (Number(d.state) === 1) {
                b.push(command('Disconnect', 'Disconnect tunnel ' + d.name + '?', { kind: CTL.DISCONNECT_TUNNEL, tunnelId: d.tunnelId }));
            }
            if (d.agentId) b.push(open('Open agent', 'agents', d.agentId));
            return b;
        },
        TunRelay: (d) => {
            const state = Number(d.state);
            if (state === 1) {
                return [command('Drain', 'Drain relay ' + d.relayId +
                    '? It takes no new agents and its agents move to the other relays.', { kind: CTL.DRAIN, relayId: d.relayId })];
            }
            if (state === 2) return [command('Resume', 'Resume relay ' + d.relayId + '?', { kind: CTL.RESUME, relayId: d.relayId })];
            return [];
        },
        TunToken: (d) => [{ label: 'Issue certificate', invoke: 'issueCert', record: d }],
        TunAgentCert: (d) => d.revoked ? [] : [{
            label: 'Revoke', danger: true,
            confirm: 'Revoke certificate ' + d.certId + '? Agents using it are refused from now on.',
            run: async () => {
                await TunData.request('PATCH', '/40/TunAgCert', { certId: d.certId, revoked: true });
                return 'Certificate revoked';
            }
        }]
    };

    window.TunActionsCore = {
        // forModel returns the actions for a record, or null when its model
        // has none.
        forModel: function(model, record) {
            return byModel[model] ? byModel[model](record) : null;
        },
        // isTunnelBase: the TUNNEL_BASE domain's names and forwards follow
        // cluster.yaml and it can't be deleted (the backend re-creates it).
        isTunnelBase: (domain) => !!domain && Number(domain.kind) === 2,
        TUNNEL_BASE_DELETE: 'The tunnel base domain is built in and can\'t be deleted; its forwards follow cluster.yaml.',
        // agentTunnelsWhere scopes the live-tunnel table to one agent.
        agentTunnelsWhere: (agentId) => 'agentId=' + agentId
    };
})();
