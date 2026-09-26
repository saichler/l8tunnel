// Edge ▸ Domains: a site with a TCP port forward, created in the UI. The
// edge binds the port (Router ports shows it), and deleting the site
// closes it again.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { uniqueName } from '../../fixtures/env';
import { DesktopNav } from '../../pages/DesktopNav';
import { Popup } from '../../pages/Popup';

const created: string[] = [];

test.afterEach(async ({ api }) => {
    for (const domain of created.splice(0)) {
        await quietly(`domain ${domain}`, () => api.remove(AREA.edge, 'EdgeDomain', 'EdgeDomain', `domain=${domain}`));
    }
});

test('a site with a TCP port forward is bound by the edge, and removed', async ({ app, api, capture }) => {
    test.setTimeout(180_000);
    const domain = uniqueName('e2e-site') + '.example.test';
    const port = 6100 + Math.floor(Math.random() * 800);
    created.push(domain);
    const nav = new DesktopNav(app);
    const table = await nav.service('edge', 'domains');
    await table.waitForResolved();
    await table.addButton().click();

    const popup = new Popup(app);
    await popup.waitForOpen();
    await popup.field('domain').fill(domain);
    await popup.field('kind').selectOption({ label: 'Site' });
    await popup.field('enabled').check(); // a new domain starts disabled
    await popup.tab('Port forwarding').click();
    await popup.root().locator('[data-inline-table="portForwards"] [data-action="add-row"]').click();
    const row = new Popup(app); // the row form stacks on top
    await expect(row.title()).toHaveText(/Port forwards/);
    await row.field('protocol').selectOption({ label: 'TCP' });
    await row.field('listenPort').fill(String(port));
    await row.field('targetPort').fill('5432');
    await row.root().locator('.probler-popup-footer button', { hasText: 'Add' }).click();
    await expect(popup.root().locator('.form-inline-table-body')).toContainText(String(port));
    await popup.saveButton().click();
    await popup.waitForAllClosed();

    const stored = await api.domainNamed(domain);
    expect(stored, 'the domain was not stored').toBeTruthy();
    expect(stored.enabled).toBe(true);
    // The forward's defaults come from the server: passthrough to this node.
    expect(stored.portForwards[0]).toMatchObject({ listenPort: port, targetPort: 5432, enabled: true });

    await table.filterBy('domain', domain);
    await expect(table.rowWith(domain)).toHaveCount(1);

    // The edge reports the new listener.
    const ports = await nav.service('edge', 'routerports');
    await expect.poll(async () => {
        await app.locator('.l8-subnav-item[data-service="domains"]').click();
        await app.locator('.l8-subnav-item[data-service="routerports"]').click();
        return (await ports.root.innerText().catch(() => '')).includes(String(port));
    }, { timeout: 120_000, intervals: [5000], message: `port ${port} never showed on Router ports` }).toBe(true);

    // Delete through the table.
    const domains = await nav.service('edge', 'domains');
    await domains.filterBy('domain', domain);
    await domains.rowById(stored.domainId).locator('[data-action="delete"]').click();
    await new Popup(app).confirmDelete();
    await expect.poll(async () => api.domainNamed(domain), { message: 'the domain was not deleted' }).toBeUndefined();
    assertNoPageErrors(capture);
});
