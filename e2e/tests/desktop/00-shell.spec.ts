// Every section and service loads cleanly: no uncaught exception, no
// console error, no failed request, and every table resolves to rows or an
// explicit empty state.
import { test, expect, assertNoPageErrors, assertNoFailedRequests } from '../../fixtures/test';
import { DesktopNav, SECTIONS, CUSTOM_VIEWS } from '../../pages/DesktopNav';

test('the dashboard shows its KPIs', async ({ app, capture }) => {
    await expect(app.locator('#tun-dashboard-kpis .layer8d-widget').first()).toBeVisible();
    expect(await app.locator('#tun-dashboard-kpis .layer8d-widget').count()).toBeGreaterThan(3);
    assertNoPageErrors(capture);
    assertNoFailedRequests(capture);
});

for (const [section, services] of Object.entries(SECTIONS)) {
    if (!services.length) continue;
    test(`${section}: every service loads`, async ({ app, capture }) => {
        const nav = new DesktopNav(app);
        for (const service of services) {
            const table = await nav.service(section, service);
            if (CUSTOM_VIEWS.has(`${section}/${service}`)) {
                await expect(table.root).not.toContainText('Loading');
                await expect(table.root).not.toContainText('unavailable');
                continue;
            }
            await table.waitForResolved();
        }
        assertNoPageErrors(capture);
        assertNoFailedRequests(capture);
    });
}

test('system: health, security, logs and data import load', async ({ app, capture }) => {
    const nav = new DesktopNav(app);
    await nav.section('system');
    await expect(app.locator('#content-area .section-container')).toBeVisible();
    for (const module of ['health', 'security', 'modules', 'logs', 'dataimport']) {
        const tab = app.locator(`.l8-module-tab[data-module="${module}"]`);
        await tab.click();
        await expect(tab).toHaveClass(/active/);
        await expect(app.locator(`.l8-module-content[data-module="${module}"]`)).toBeVisible();
        await app.waitForTimeout(800);
    }
    assertNoPageErrors(capture);
    assertNoFailedRequests(capture);
});
