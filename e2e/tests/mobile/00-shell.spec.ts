// The mobile bundle: the home screen, a tap-through path, and every
// service's list resolving cleanly.
import { test, expect, assertNoPageErrors, assertNoFailedRequests } from '../../fixtures/test';
import { MobileNav, MOBILE_NAV } from '../../pages/MobileNav';

test('the home screen shows the KPIs and every module', async ({ mobile, capture }) => {
    await expect(mobile.locator('#tun-m-kpis .nav-stat-card').first()).toBeVisible();
    for (const module of Object.keys(MOBILE_NAV)) {
        await expect(mobile.locator(`.nav-card[data-module="${module}"]`)).toBeVisible();
    }
    // Every card leads somewhere.
    await expect(mobile.locator('.nav-card.coming-soon')).toHaveCount(0);
    assertNoPageErrors(capture);
    assertNoFailedRequests(capture);
});

test('tapping Access, then Tokens, opens the token list', async ({ mobile, capture }) => {
    const nav = new MobileNav(mobile);
    await nav.open('Access', 'Tokens');
    await expect(nav.addButton()).toHaveText(/Add Token/);
    await expect(nav.cards().first()).toBeVisible();
    assertNoPageErrors(capture);
});

for (const [module, subs] of Object.entries(MOBILE_NAV)) {
    test(`${module}: every service loads`, async ({ mobile, capture }) => {
        const nav = new MobileNav(mobile);
        for (const [sub, services] of Object.entries(subs)) {
            for (const service of services) {
                await nav.service(module, sub, service);
                if (service === 'routerports') {
                    const box = mobile.locator('#tun-m-router-ports');
                    await expect(box).toBeVisible();
                    await expect(box).not.toContainText('Loading');
                    await expect(box).not.toContainText('unavailable');
                    continue;
                }
                // Rows, or an explicit empty state; never a blank list.
                await expect.poll(async () => (await nav.cards().count()) > 0 ||
                    /No |empty/i.test(await mobile.locator('#service-table-container, .l8sys-container, .data-list-content').first().innerText().catch(() => '')),
                    { message: `${module}/${service} rendered neither cards nor an empty state` }).toBe(true);
            }
        }
        assertNoPageErrors(capture);
        assertNoFailedRequests(capture);
    });
}
