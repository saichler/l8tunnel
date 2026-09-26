// Access ▸ Tokens: issuing shows the token once, the record opens with its
// actions, and deleting revokes it.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { uniqueName } from '../../fixtures/env';
import { DesktopNav } from '../../pages/DesktopNav';
import { Popup } from '../../pages/Popup';
import { ReferencePicker } from '../../pages/ReferencePicker';

const created: string[] = [];

test.afterEach(async ({ api }) => {
    for (const name of created.splice(0)) {
        await quietly(`token ${name}`, async () => {
            const tok = await api.tokenNamed(name);
            if (tok) await api.revokeToken(tok.tokenId);
        });
    }
});

test('issue a token in the UI, see it once, then revoke it', async ({ app, api, capture }) => {
    const name = uniqueName('e2e-tok');
    created.push(name);
    const table = await new DesktopNav(app).service('access', 'tokens');
    await table.waitForResolved();
    await table.addButton().click();

    const popup = new Popup(app);
    await popup.waitForOpen('Issue token');
    await popup.field('tokenName').fill(name);
    await popup.tab('Policy').click();
    await popup.addTag('policy.names', 'e2e-*');
    await popup.saveButton().click();

    // The show-once popup replaces the form and carries the token string.
    await expect(popup.root().locator('.tun-secret-value')).toHaveValue(/^l8t_[0-9a-f]+_/);
    await popup.close();
    await popup.waitForAllClosed();

    const stored = await api.tokenNamed(name);
    expect(stored, 'the token was not stored').toBeTruthy();
    expect(stored.policy?.names).toEqual(['e2e-*']);

    await table.filterBy('name', name);
    await expect(table.rowWith(name)).toHaveCount(1);

    // The record opens with its actions.
    await table.rowWith(name).locator('td').first().click();
    await popup.waitForOpen();
    await expect(popup.actions().first()).toBeVisible();
    await popup.close();

    // Delete revokes, after a confirmation.
    app.once('dialog', (d) => d.accept());
    await table.rowById(stored.tokenId).locator('[data-action="delete"]').click();
    await expect.poll(async () => api.tokenNamed(name), { message: 'the token was not revoked' }).toBeUndefined();
    await expect(table.rowWith(name)).toHaveCount(0);
    assertNoPageErrors(capture);
});

test('reserve a name for a token through the reference picker', async ({ app, api, capture }) => {
    const tokName = uniqueName('e2e-rtok');
    created.push(tokName); // revoking the token drops its reservations too
    const tok = await api.issueToken(tokName);
    const name = uniqueName('e2e-box');

    const table = await new DesktopNav(app).service('access', 'reservations');
    await table.waitForResolved();
    await table.addButton().click();
    const popup = new Popup(app);
    await popup.waitForOpen();
    await popup.field('name').fill(name);
    await popup.field('tokenId').click();
    await new ReferencePicker(app).choose(tokName, tok.tokenId);
    await expect(popup.field('tokenId')).toHaveValue(tokName);
    await popup.saveButton().click();
    await popup.waitForAllClosed();

    const rows = await api.query(AREA.access, 'TunResv', `select * from TunReservation where name=${name}`);
    expect(rows.find((r) => r.name === name)?.tokenId).toBe(tok.tokenId);
    await table.filterBy('name', name);
    await expect(table.rowWith(name)).toHaveCount(1);
    assertNoPageErrors(capture);
});
