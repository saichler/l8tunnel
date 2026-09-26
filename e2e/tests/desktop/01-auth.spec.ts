// The real login path: the form, the redirect to the app, and a refusal.
import { test, expect } from '@playwright/test';
import { LoginPage } from '../../pages/LoginPage';
import { waitForDesktopReady } from '../../fixtures/test';
import { ENV } from '../../fixtures/env';

test('admin logs in through the form and lands on the dashboard', async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.login(ENV.user, ENV.pass);
    await expect(page).toHaveURL(/app\.html/);
    await waitForDesktopReady(page);
    await expect(page.locator('#tun-dashboard-kpis')).toBeVisible();
});

test('a wrong password is refused and stays on the login page', async ({ page }) => {
    const login = new LoginPage(page);
    await login.goto();
    await login.login(ENV.user, 'not-the-password');
    await expect(login.error()).toBeVisible();
    await expect(page).not.toHaveURL(/app\.html/);
});

test('the root redirects to the login page', async ({ page }) => {
    await page.goto('/');
    await expect(page).toHaveURL(/l8ui\/login/);
});
