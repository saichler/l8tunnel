// A row click opens the record in every table that has rows, with a title
// and its fields, and without errors.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { DesktopNav, SECTIONS, CUSTOM_VIEWS } from '../../pages/DesktopNav';
import { Popup } from '../../pages/Popup';

for (const [section, services] of Object.entries(SECTIONS)) {
    if (!services.length) continue;
    test(`${section}: a row opens its record`, async ({ app, capture }) => {
        const nav = new DesktopNav(app);
        const popup = new Popup(app);
        for (const service of services) {
            if (CUSTOM_VIEWS.has(`${section}/${service}`)) continue;
            const table = await nav.service(section, service);
            if ((await table.waitForResolved()) === 'empty') continue;
            await table.rows().first().locator('td').first().click();
            await popup.waitForOpen();
            await expect(popup.title(), `${section}/${service}: the record popup has no title`).not.toHaveText('');
            expect(await popup.body().locator('.form-group').count(), `${section}/${service}: no fields`).toBeGreaterThan(0);
            await popup.close();
            await popup.waitForAllClosed();
        }
        assertNoPageErrors(capture);
    });
}
