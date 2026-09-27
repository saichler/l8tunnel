// Load balancing on mobile: Edge ▸ Domains. A port forward's Add, Edit and
// card open the Port forward popup with its targets and balancing, and the
// domain's Add and Edit save.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { uniqueName } from '../../fixtures/env';
import { MobileNav } from '../../pages/MobileNav';

test('a port forward\'s targets and balancing on mobile', async ({ mobile, api, capture }) => {
    test.setTimeout(120_000);
    const domain = uniqueName('e2e-mlb') + '.example.test';
    const port = 6100 + Math.floor(Math.random() * 800);
    try {
        const nav = new MobileNav(mobile);
        await nav.service('edge', 'edge', 'domains');

        // Add: a site whose HTTPS forward balances over two targets.
        await nav.addButton().click();
        await nav.waitForPopup('Add Domain');
        await nav.popup().locator('input[name="domain"]').fill(domain);
        await nav.popup().locator('select[name="kind"]').selectOption({ label: 'Site' });
        await nav.popup().locator('[data-inline-table="portForwards"] [data-action="add-row"]').click();
        await nav.waitForPopup('Add Port forward');
        await nav.popup().locator('select[name="protocol"]').selectOption({ label: 'HTTPS' });
        await nav.popup().locator('input[name="listenPort"]').fill(String(port));
        await nav.popup().locator('select[name="mode"]').selectOption({ label: 'Passthrough' });
        await nav.popup().locator('select[name="lb"]').selectOption({ label: 'Round robin' });
        for (const [host, weight] of [['10.0.1.1', 2], ['10.0.1.2', 1]] as const) {
            await nav.popup().locator('[data-inline-table="targets"] [data-action="add-row"]').click();
            await nav.waitForPopup('Add Targets');
            await nav.popup().locator('input[name="host"]').fill(host);
            await nav.popup().locator('input[name="port"]').fill('8443');
            await nav.popup().locator('input[name="weight"]').fill(String(weight));
            await nav.popup().locator('.mobile-popup-btn-save').click();
            await nav.waitForPopup('Add Port forward');
            await expect(nav.popup().locator('[data-inline-table="targets"]')).toContainText(host);
        }
        await nav.popup().locator('.mobile-popup-btn-save').click();
        await nav.waitForPopup('Add Domain');
        await nav.popup().locator('.mobile-popup-btn-save').click();
        await expect.poll(async () => api.domainNamed(domain), { message: 'the domain was not stored' }).toBeTruthy();
        expect((await api.domainNamed(domain)).portForwards[0]).toMatchObject({
            listenPort: port, mode: 2, lb: 1, targetKind: 1,
            targets: [{ host: '10.0.1.1', port: 8443, weight: 2 }, { host: '10.0.1.2', port: 8443, weight: 1 }],
        });
        await nav.filter('domain', domain);

        // Detail: the forward's card opens the popup read-only.
        await nav.card(domain).click();
        await nav.waitForPopup();
        await nav.popup().locator('.mobile-form-tab', { hasText: 'Port forwarding' }).click();
        await nav.popup().locator('[data-inline-table="portForwards"] .mobile-form-inline-card').first().click();
        await nav.waitForPopup('Port forward details');
        await expect(nav.popup().locator('[data-inline-table="targets"]')).toContainText('10.0.1.2');
        await expect(nav.popup()).toContainText('Round robin');
        await expect(nav.popup().locator('[name="lb"]')).toHaveCount(0);
        await mobile.evaluate(() => (window as any).Layer8MPopup.close());
        await mobile.evaluate(() => (window as any).Layer8MPopup.close());

        // Edit: the forward's Edit opens the popup with its targets; switch
        // the algorithm and save.
        await nav.card(domain).locator('.mobile-edit-table-action-btn.edit').click();
        await nav.waitForPopup();
        await nav.popup().locator('[data-inline-table="portForwards"] [data-action="edit-row"]').first().click();
        await nav.waitForPopup('Edit Port forward');
        await expect(nav.popup().locator('[data-inline-table="targets"]')).toContainText('10.0.1.1');
        await nav.popup().locator('select[name="lb"]').selectOption({ label: 'Source hash' });
        await nav.popup().locator('.mobile-popup-btn-save').click();
        await nav.waitForPopup('Edit Domain');
        await nav.popup().locator('.mobile-popup-btn-save').click();

        await expect.poll(async () => (await api.domainNamed(domain))?.portForwards?.[0]?.lb, { message: 'the algorithm was not saved' }).toBe(3);
        expect((await api.domainNamed(domain)).portForwards[0].targets).toMatchObject([
            { host: '10.0.1.1', port: 8443, weight: 2 }, { host: '10.0.1.2', port: 8443, weight: 1 },
        ]);
        assertNoPageErrors(capture);
    } finally {
        await quietly(`domain ${domain}`, () => api.remove(AREA.edge, 'EdgeDomain', 'EdgeDomain', `domain=${domain}`));
    }
});
