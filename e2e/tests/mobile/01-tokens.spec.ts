// Access ▸ Tokens on mobile: issue shows the token once, the card opens
// with its actions, and deleting revokes after a confirmation.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { quietly } from '../../fixtures/api';
import { uniqueName } from '../../fixtures/env';
import { MobileNav } from '../../pages/MobileNav';

test('issue a token on mobile, see it once, open it and revoke it', async ({ mobile, api, capture }) => {
    const name = uniqueName('e2e-mtok');
    try {
        const nav = new MobileNav(mobile);
        await nav.service('access', 'access', 'tokens');
        await nav.addButton().click();
        await nav.waitForPopup('Issue token');
        await nav.popup().locator('input[name="tokenName"]').fill(name);
        await nav.popup().locator('.mobile-popup-btn-save').click();
        await expect(nav.popup().locator('.tun-secret-value')).toHaveValue(/^l8t_[0-9a-f]+_/);
        await mobile.evaluate(() => (window as any).Layer8MPopup.close());

        const stored = await api.tokenNamed(name);
        expect(stored, 'the token was not stored').toBeTruthy();

        await nav.filter('name', name);
        await expect(nav.card(name)).toHaveCount(1);
        await nav.card(name).click();
        await nav.waitForPopup(/Token Details/);
        await expect(nav.popup().locator('.tun-action-bar button').first()).toBeVisible();
        await mobile.evaluate(() => (window as any).Layer8MPopup.close());

        await nav.card(name).locator('.mobile-edit-table-action-btn.delete').click();
        const confirm = mobile.locator('.mobile-confirm');
        await expect(confirm.locator('.mobile-confirm-title')).toHaveText('Revoke token');
        await confirm.locator('.mobile-confirm-btn-danger').click();
        await expect.poll(async () => api.tokenNamed(name), { message: 'the token was not revoked' }).toBeUndefined();
        assertNoPageErrors(capture);
    } finally {
        await quietly(`token ${name}`, async () => {
            const tok = await api.tokenNamed(name);
            if (tok) await api.revokeToken(tok.tokenId);
        });
    }
});
