// The top-most Layer8DPopup (desktop).
import { Page, Locator, expect } from '@playwright/test';

export class Popup {
    constructor(private page: Page) {}

    root(): Locator { return this.page.locator('.probler-popup-overlay.active').last(); }
    title(): Locator { return this.root().locator('.probler-popup-title'); }
    body(): Locator { return this.root().locator('.probler-popup-body'); }
    tab(name: string): Locator { return this.root().locator('.probler-popup-tab', { hasText: name }); }
    field(name: string): Locator { return this.root().locator(`[name="${name}"]`); }
    saveButton(): Locator { return this.root().locator('.probler-popup-footer .btn-primary, .probler-popup-footer .layer8d-btn-primary').first(); }
    actions(): Locator { return this.root().locator('.tun-action-bar button'); }

    async waitForOpen(title?: string | RegExp): Promise<void> {
        await expect(this.root()).toBeVisible();
        if (title) await expect(this.title()).toHaveText(title);
    }

    async close(): Promise<void> {
        await this.root().locator('.probler-popup-close').click();
    }

    async waitForAllClosed(): Promise<void> {
        await expect(this.page.locator('.probler-popup-overlay.active')).toHaveCount(0);
    }

    /** Confirms l8ui's "Confirm Delete" popup. */
    async confirmDelete(): Promise<void> {
        await this.waitForOpen('Confirm Delete');
        await this.saveButton().click();
    }

    /** Adds a tag to a tags field (Enter commits it). */
    async addTag(name: string, value: string): Promise<void> {
        const input = this.root().locator(`[data-tags-value="${name}"]`).locator('xpath=..').locator('.l8-tags-input');
        await input.fill(value);
        await input.press('Enter');
    }
}
