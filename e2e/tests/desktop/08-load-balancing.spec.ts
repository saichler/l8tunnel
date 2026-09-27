// Load balancing on the edge: Edge ▸ Domains ▸ Port forwarding. The port
// forwards table stays protocol, in port and to port; a forward's Add, Edit
// and detail popups show its Targets table and the balancing settings.
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

// addTarget adds one row to the forward popup's Targets table.
async function addTarget(app, forward: Popup, host: string, port: number, weight: number) {
    await forward.root().locator('[data-inline-table="targets"] [data-action="add-row"]').click();
    const row = new Popup(app);
    await expect(row.title()).toHaveText(/Targets/);
    await row.waitForFocus();
    await row.field('host').fill(host);
    await row.field('port').fill(String(port));
    await row.field('weight').fill(String(weight));
    await row.root().locator('.probler-popup-footer button', { hasText: 'Add' }).click();
    await expect(forward.root().locator('[data-inline-table="targets"] .form-inline-table-body')).toContainText(host);
}

test('a port forward\'s detail edits its targets and balancing; the table stays the same', async ({ app, api, capture }) => {
    test.setTimeout(180_000);
    const domain = uniqueName('e2e-lb') + '.example.test';
    const port = 6100 + Math.floor(Math.random() * 800);
    created.push(domain);
    const nav = new DesktopNav(app);
    const table = await nav.service('edge', 'domains');
    await table.waitForResolved();

    // Add: a site whose HTTPS forward balances over two weighted targets.
    await table.addButton().click();
    const popup = new Popup(app);
    await popup.waitForOpen();
    await popup.waitForFocus();
    await popup.field('domain').fill(domain);
    await popup.field('kind').selectOption({ label: 'Site' });
    await popup.field('enabled').check();
    await popup.tab('Port forwarding').click();
    await popup.root().locator('[data-inline-table="portForwards"] [data-action="add-row"]').click();
    const forward = new Popup(app);
    await expect(forward.title()).toHaveText(/Port forward/);
    await forward.waitForFocus();
    await forward.field('protocol').selectOption({ label: 'HTTPS' });
    await forward.field('listenPort').fill(String(port));
    await forward.field('mode').selectOption({ label: 'Passthrough' });
    await forward.field('lb').selectOption({ label: 'Round robin' });
    await forward.field('healthType').selectOption({ label: 'TCP' });
    await addTarget(app, forward, '10.0.0.1', 8443, 3);
    await addTarget(app, forward, '10.0.0.2', 8443, 1);
    await forward.root().locator('.probler-popup-footer button', { hasText: 'Add' }).click();

    // The forwards table is unchanged: protocol, in port, to port.
    const forwards = popup.root().locator('[data-inline-table="portForwards"]');
    await expect(forwards.locator('.form-inline-table-body')).toContainText(String(port));
    const headers = (await forwards.locator('.form-inline-table-header span').allTextContents()).filter((h) => h.trim());
    expect(headers).toEqual(['Protocol', 'In port', 'To port']);
    await popup.saveButton().click();
    await popup.waitForAllClosed();

    let stored = await api.domainNamed(domain);
    expect(stored, 'the domain was not stored').toBeTruthy();
    expect(stored.portForwards[0]).toMatchObject({
        listenPort: port, mode: 2, targetKind: 1, lb: 1, healthType: 2,
        targets: [{ host: '10.0.0.1', port: 8443, weight: 3 }, { host: '10.0.0.2', port: 8443, weight: 1 }],
    });

    // Edit: the forward's popup shows its targets; switch the algorithm and
    // disable the second target.
    await table.filterBy('domain', domain);
    await table.rowById(stored.domainId).locator('[data-action="edit"]').click();
    const edit = new Popup(app);
    await edit.waitForOpen();
    await edit.tab('Port forwarding').click();
    await edit.root().locator('[data-inline-table="portForwards"] [data-action="edit-row"]').first().click();
    const editForward = new Popup(app);
    await expect(editForward.title()).toHaveText(/Port forward/);
    const targets = editForward.root().locator('[data-inline-table="targets"] .form-inline-table-body');
    await expect(targets).toContainText('10.0.0.1');
    await expect(targets).toContainText('10.0.0.2');
    await editForward.field('lb').selectOption({ label: 'Least connections' });
    await editForward.root().locator('[data-inline-table="targets"] [data-action="edit-row"]').nth(1).click();
    const target = new Popup(app);
    await expect(target.title()).toHaveText(/Targets/);
    await target.field('disabled').check();
    await target.root().locator('.probler-popup-footer button', { hasText: 'Update' }).click();
    await editForward.root().locator('.probler-popup-footer button', { hasText: 'Update' }).click();
    await edit.saveButton().click();
    await edit.waitForAllClosed();

    await expect.poll(async () => (await api.domainNamed(domain))?.portForwards?.[0]?.lb, { message: 'the algorithm was not saved' }).toBe(2);
    stored = await api.domainNamed(domain);
    expect(stored.portForwards[0].targets).toMatchObject([
        { host: '10.0.0.1', port: 8443, weight: 3 },
        { host: '10.0.0.2', port: 8443, weight: 1, disabled: true },
    ]);
    expect(stored.portForwards[0].targets[0].disabled ?? false).toBe(false);

    // Detail: clicking the forward shows the same popup, read-only.
    await table.rowById(stored.domainId).locator('td').first().click();
    const detail = new Popup(app);
    await detail.waitForOpen();
    await detail.tab('Port forwarding').click();
    await detail.root().locator('[data-inline-table="portForwards"] .form-inline-table-row').first().click();
    const view = new Popup(app);
    await expect(view.title()).toHaveText(/Port forward/);
    await expect(view.root().locator('[data-inline-table="targets"] .form-inline-table-body')).toContainText('10.0.0.2');
    // Read-only: values as text, no inputs or row buttons.
    await expect(view.body()).toContainText('Least connections');
    await expect(view.field('lb')).toHaveCount(0);
    await expect(view.root().locator('[data-inline-table="targets"] [data-action="add-row"]')).toHaveCount(0);
    assertNoPageErrors(capture);
});
