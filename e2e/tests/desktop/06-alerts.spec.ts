// Alerts ▸ Rules: create a rule in the UI, see it stored, delete it.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { uniqueName } from '../../fixtures/env';
import { DesktopNav } from '../../pages/DesktopNav';
import { Popup } from '../../pages/Popup';

test('create and delete an alert rule', async ({ app, api, capture }) => {
    const name = uniqueName('e2e-rule');
    const find = async () => (await api.query(AREA.alerts, 'TunAlert', `select * from TunAlertRule where name=${name}`))
        .find((r) => r.name === name);
    try {
        const table = await new DesktopNav(app).service('alerts', 'rules');
        await table.waitForResolved();
        await table.addButton().click();
        const popup = new Popup(app);
        await popup.waitForOpen();
        await popup.field('name').fill(name);
        await popup.field('condition').selectOption({ label: 'Certificate expiring' });
        await popup.field('threshold').fill('14');
        await popup.field('enabled').check();
        // A rule needs somewhere to send: one webhook target.
        await popup.tab('Targets').click();
        await popup.root().locator('[data-action="add-row"]').click();
        const target = new Popup(app);
        await expect(target.title()).toHaveText(/Notification Targets/);
        await target.field('channel').selectOption({ label: 'Webhook' });
        await target.field('endpoint').fill('https://hooks.example.test/e2e');
        await target.root().locator('.probler-popup-footer button', { hasText: 'Add' }).click();
        await expect(popup.root().locator('.form-inline-table-body')).toContainText('hooks.example.test');
        await popup.saveButton().click();
        await popup.waitForAllClosed();

        const stored = await find();
        expect(stored, 'the rule was not stored').toMatchObject({ threshold: 14, enabled: true });

        await table.filterBy('name', name);
        await expect(table.rowWith(name)).toHaveCount(1);
        await table.rowById(stored.ruleId).locator('[data-action="delete"]').click();
        await popup.confirmDelete();
        await expect.poll(find, { message: 'the rule was not deleted' }).toBeUndefined();
        assertNoPageErrors(capture);
    } finally {
        await quietly(`rule ${name}`, () => api.remove(AREA.alerts, 'TunAlert', 'TunAlertRule', `name=${name}`));
    }
});
