// The Layer8D reference picker a reference field opens.
import { Page, Locator, expect } from '@playwright/test';

export class ReferencePicker {
    constructor(private page: Page) {}

    list(): Locator { return this.page.locator('.layer8d-refpicker-list').last(); }
    search(): Locator { return this.page.locator('.layer8d-refpicker-search input').last(); }
    item(id: string): Locator { return this.list().locator(`[data-id="${id}"]`); }
    selectButton(): Locator { return this.page.locator('.layer8d-refpicker-select-btn').last(); }

    /** Searches for text and picks the row with this ID. */
    async choose(text: string, id: string): Promise<void> {
        await expect(this.list()).toBeVisible();
        await this.search().fill(text);
        await expect(this.item(id)).toBeVisible();
        await this.item(id).click();
        if (await this.selectButton().count()) await this.selectButton().click();
        await expect(this.page.locator('.layer8d-refpicker-overlay')).toHaveCount(0);
    }
}
