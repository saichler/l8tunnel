// The desktop shell's navigation: top-level sections and their service tabs.
import { Page, expect } from '@playwright/test';
import { DesktopTable } from './DesktopTable';

/** Every section and its services (tun/tun-section-config.js). */
export const SECTIONS: Record<string, string[]> = {
    dashboard: [],
    tunnels: ['agents', 'live', 'relays', 'edgenodes'],
    access: ['tokens', 'reservations', 'gwkeys', 'agentcerts'],
    edge: ['domains', 'routerports'],
    alerts: ['rules', 'deliveries', 'integrations'],
    system: []
};

/** Services rendered by a custom view instead of a table. */
export const CUSTOM_VIEWS = new Set(['edge/routerports']);

export class DesktopNav {
    constructor(private page: Page) {}

    /**
     * Opens a section. Clicking the active section's link reloads it, and a
     * reload that finishes after a tab click resets the tab, so an active
     * section is left alone.
     */
    async section(key: string): Promise<void> {
        const link = this.page.locator(`.nav-link[data-section="${key}"]`);
        if (!/\bactive\b/.test((await link.getAttribute('class')) || '')) await link.click();
        await expect(link).toHaveClass(/active/);
    }

    /** Opens a service's tab and returns its table. */
    async service(section: string, service: string): Promise<DesktopTable> {
        await this.section(section);
        const tab = this.page.locator(`.l8-subnav-item[data-service="${service}"]`);
        await expect(tab).toBeVisible();
        await tab.click();
        await expect(tab).toHaveClass(/active/);
        return new DesktopTable(this.page, section, service);
    }
}
