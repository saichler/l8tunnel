// Mobile dashboard: the downloads and the guide on the home screen only.
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { MobileNav } from '../../pages/MobileNav';

test('the home screen offers the downloads and the guide, and hides them in a module', async ({ mobile, capture }) => {
    await expect(mobile.locator('#tun-m-guide .tun-download-btn')).toHaveCount(2);
    const guide = mobile.locator('#tun-m-guide details.tun-guide');
    await guide.locator('> summary').click();
    expect(await guide.locator('details.tun-guide-topic').count()).toBeGreaterThanOrEqual(8);

    await new MobileNav(mobile).open('Access', 'Tokens');
    await expect(mobile.locator('#tun-m-guide')).toBeHidden();
    await expect(mobile.locator('#tun-m-kpis')).toBeHidden();
    assertNoPageErrors(capture);
});
