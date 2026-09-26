// The mobile shell: home cards, module cards, service lists and popups.
import { Page, Locator, expect } from '@playwright/test';

/** Every mobile module, its sub-module and services (m/nav-configs). */
export const MOBILE_NAV: Record<string, Record<string, string[]>> = {
    tunnels: { tunnels: ['agents', 'live', 'relays', 'edgenodes'] },
    access: { access: ['tokens', 'reservations', 'gwkeys', 'agentcerts'] },
    edge: { edge: ['domains', 'routerports'] },
    alerts: { alerts: ['rules', 'deliveries', 'integrations'] },
    system: { health: ['health-monitor'], security: ['users', 'roles', 'credentials', 'events'] }
};

export class MobileNav {
    constructor(private page: Page) {}

    /** Taps a home card, then a module card, as a user would. */
    async open(moduleLabel: string, serviceLabel: string): Promise<void> {
        await this.page.locator('.nav-card', { hasText: moduleLabel }).first().click();
        await this.page.locator('.nav-card', { hasText: serviceLabel }).first().click();
    }

    /** Goes straight to a service (the nav's own entry point). */
    async service(module: string, sub: string, service: string): Promise<void> {
        await this.page.evaluate(([m, s, v]) => (window as any).Layer8MNav.navigateToService(m, s, v), [module, sub, service]);
    }

    list(): Locator { return this.page.locator('#service-table-container'); }
    cards(): Locator {
        return this.page.locator('#service-table-container .mobile-edit-table-card, #service-table-container .mobile-table-card');
    }
    card(text: string): Locator { return this.cards().filter({ hasText: text }); }
    addButton(): Locator { return this.list().locator('.mobile-edit-table-add-btn'); }
    emptyState(): Locator { return this.list().locator('.mobile-edit-table-empty, .mobile-table-empty, .l8-empty-state'); }

    /** Filters the list and waits for the refetch. */
    async filter(column: string, value: string): Promise<void> {
        await this.list().locator('.mobile-edit-table-column-select').selectOption(column);
        const settled = this.page.waitForResponse((r) => r.url().includes('body=') && r.ok(), { timeout: 15_000 }).catch(() => null);
        await this.list().locator('.mobile-edit-table-search-input').fill(value);
        await settled;
        await this.page.waitForTimeout(400);
    }

    popup(): Locator { return this.page.locator('.mobile-popup').last(); }

    async waitForPopup(title?: string | RegExp): Promise<void> {
        await expect(this.popup()).toBeVisible();
        if (title) await expect(this.popup().locator('.mobile-popup-title')).toHaveText(title);
    }
}
