// The suite's fixture: every spec imports test/expect from here.
//   api     an authenticated REST client
//   app     a page signed in to the desktop shell
//   mobile  a page signed in to the mobile shell
//   capture every uncaught exception, console error and failed request the
//           page raised, so a missing script or a dead handler fails the spec
//           that hit it (FailFastNoSilentFallback), not just a dedicated one.
import { test as base, expect, Page, BrowserContext } from '@playwright/test';
import { Api } from './api';
import { ENV } from './env';

export interface Capture {
    pageErrors: string[];
    consoleErrors: string[];
    failedRequests: string[];
}

function attach(page: Page): Capture {
    const cap: Capture = { pageErrors: [], consoleErrors: [], failedRequests: [] };
    page.on('pageerror', (e) => cap.pageErrors.push(`${e.name}: ${e.message}`));
    page.on('console', (m) => {
        if (m.type() === 'error') cap.consoleErrors.push(m.text());
    });
    page.on('response', (r) => {
        if (r.status() >= 400) cap.failedRequests.push(`${r.request().method()} ${r.url()} -> ${r.status()}`);
    });
    return cap;
}

/**
 * The app keeps its bearer token in sessionStorage, which Playwright's
 * storageState doesn't carry, so the session is seeded before any script
 * runs, as the login page would leave it.
 */
async function seedSession(context: BrowserContext, token: string): Promise<void> {
    await context.addInitScript(([t, u]) => {
        sessionStorage.setItem('bearerToken', t as string);
        sessionStorage.setItem('currentUser', u as string);
    }, [token, ENV.user]);
}

/** The desktop shell is ready once the dashboard section has rendered. */
export async function waitForDesktopReady(page: Page): Promise<void> {
    await expect(page.locator('#content-area .section-container, #content-area .l8-section').first(),
        'the desktop shell never rendered its first section').toBeVisible({ timeout: 45_000 });
}

/** The mobile shell is ready once the home screen has rendered. */
export async function waitForMobileReady(page: Page): Promise<void> {
    await expect(page.locator('#tun-m-kpis, .nav-card-grid').first(),
        'the mobile shell never rendered its home screen').toBeVisible({ timeout: 45_000 });
}

type Fixtures = { api: Api; capture: Capture; app: Page; mobile: Page };

export const test = base.extend<Fixtures>({
    api: async ({}, use) => {
        const api = await Api.login();
        await use(api);
        await api.dispose();
    },
    capture: async ({ page }, use) => {
        await use(attach(page));
    },
    app: async ({ page, context, api, capture }, use) => {
        void capture; // listeners before the first navigation
        await seedSession(context, api.token);
        await page.goto(ENV.desktopShell);
        await waitForDesktopReady(page);
        await use(page);
    },
    mobile: async ({ page, context, api, capture }, use) => {
        void capture;
        await seedSession(context, api.token);
        await page.goto(ENV.mobileShell);
        await waitForMobileReady(page);
        await use(page);
    }
});

export { expect };

/** Fails on any uncaught exception or console error the page raised. */
export function assertNoPageErrors(cap: Capture): void {
    expect(cap.pageErrors, `uncaught exceptions:\n  ${cap.pageErrors.join('\n  ')}`).toEqual([]);
    expect(cap.consoleErrors, `console errors:\n  ${cap.consoleErrors.join('\n  ')}`).toEqual([]);
}

/** Fails on any HTTP error response, except those a spec expects. */
export function assertNoFailedRequests(cap: Capture, allow: RegExp[] = []): void {
    const failed = cap.failedRequests.filter((f) => !allow.some((a) => a.test(f)));
    expect(failed, `failed requests:\n  ${failed.join('\n  ')}`).toEqual([]);
}
