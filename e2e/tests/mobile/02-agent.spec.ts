// A real agent on mobile: its card is online, its details list its tunnel,
// and a clean stop parks it.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { quietly } from '../../fixtures/api';
import { RunningAgent } from '../../fixtures/agent';
import { uniqueName } from '../../fixtures/env';
import { MobileNav } from '../../pages/MobileNav';

test('an agent shows online with its tunnel, then parks when it stops', async ({ mobile, api, capture }) => {
    test.setTimeout(150_000);
    const tokName = uniqueName('e2e-mrt');
    const tunnel = uniqueName('e2e-mbox');
    const tok = await api.issueToken(tokName);
    const agent = await RunningAgent.start(tok.token, tunnel);
    try {
        const nav = new MobileNav(mobile);
        await nav.service('tunnels', 'tunnels', 'agents');
        await expect.poll(async () => {
            await nav.filter('tokenName', tokName);
            return nav.card(tokName).count();
        }, { timeout: 45_000, message: `the agent never showed; agent log:\n${agent.log()}` }).toBe(1);
        await expect(nav.card(tokName)).toContainText('Online');
        await nav.card(tokName).click();
        await nav.waitForPopup();
        await expect(nav.popup().locator('.tun-related')).toContainText(tunnel);
        await mobile.evaluate(() => (window as any).Layer8MPopup.close());

        await agent.stop();
        await expect.poll(async () => {
            await nav.filter('tokenName', tokName);
            return nav.card(tokName).textContent(); // innerText is upper-cased by CSS
        }, { timeout: 45_000, message: 'the agent never went to grace' }).toContain('Grace');
        assertNoPageErrors(capture);
    } finally {
        await agent.stop();
        await quietly(`token ${tokName}`, () => api.revokeToken(tok.tokenId));
    }
});
