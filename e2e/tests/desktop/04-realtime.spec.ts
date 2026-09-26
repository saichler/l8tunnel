// Live tables follow a real agent without a reload: its tunnel and agent
// rows appear when it connects and go to grace when it stops.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { RunningAgent } from '../../fixtures/agent';
import { ENV, uniqueName } from '../../fixtures/env';
import { DesktopNav } from '../../pages/DesktopNav';
import { Popup } from '../../pages/Popup';

test('a connecting and stopping agent updates the live tables in place', async ({ app, api, capture }) => {
    test.setTimeout(150_000);
    const tokName = uniqueName('e2e-rt');
    const tunnel = uniqueName('e2e-rtbox');
    const tok = await api.issueToken(tokName);
    let agent: RunningAgent | undefined;
    try {
        const nav = new DesktopNav(app);
        const live = await nav.service('tunnels', 'live');
        await live.waitForResolved();
        await live.filterBy('name', tunnel);
        await expect(live.rowWith(tunnel)).toHaveCount(0);

        agent = await RunningAgent.start(tok.token, tunnel, 'ssh');
        await expect(live.rowWith(tunnel), `the tunnel never appeared; agent log:\n${agent.log()}`)
            .toHaveCount(1, { timeout: 45_000 });
        await expect(live.rowWith(tunnel)).toContainText('Active');

        // The tunnel's Connect action shows the exact SSH commands.
        const rec = (await api.query(AREA.live, 'TunLive', `select * from TunLiveTunnel where name=${tunnel}`))
            .find((t) => t.name === tunnel);
        await live.rowWith(tunnel).locator('td').nth(1).click();
        const detail = new Popup(app);
        await detail.waitForOpen();
        await detail.actions().filter({ hasText: 'Connect' }).click();
        const connect = new Popup(app);
        await connect.waitForOpen(`Connect to ${tunnel}`);
        await connect.root().locator('.tun-connect-user').fill('alice');
        const cmds = connect.root().locator('.tun-secret-value');
        await expect(cmds.nth(0)).toHaveValue(`ssh -p ${rec.publicPort} alice@${ENV.tunnelBase}`);
        await expect(cmds.nth(1)).toHaveValue(`ssh -o ProxyCommand="l8tunnel connect %h" alice@${tunnel}.${ENV.tunnelBase}`);
        await connect.close();
        await detail.close();
        await detail.waitForAllClosed();

        // The agent's own row, and its tunnels in its details.
        const agents = await nav.service('tunnels', 'agents');
        await agents.waitForResolved();
        await agents.filterBy('tokenName', tokName);
        const agentRow = agents.rowWith(tokName);
        await expect(agentRow).toHaveCount(1, { timeout: 30_000 });
        await expect(agentRow).toContainText('Online');
        await agentRow.locator('td').nth(1).click();
        const popup = new Popup(app);
        await popup.waitForOpen();
        await expect(popup.root().locator('.tun-related')).toContainText(tunnel);
        await popup.close();

        // A clean stop parks the agent and its tunnel.
        await agent.stop();
        await expect(agentRow).toContainText('Grace', { timeout: 45_000 });
        const again = await nav.service('tunnels', 'live');
        await again.filterBy('name', tunnel);
        await expect(again.rowWith(tunnel)).toContainText('Grace', { timeout: 45_000 });
        assertNoPageErrors(capture);
    } finally {
        if (agent) await agent.stop();
        await quietly(`token ${tokName}`, () => api.revokeToken(tok.tokenId));
    }
});
