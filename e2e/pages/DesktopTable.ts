// One service's Layer8DTable on the desktop.
import { Page, Locator, expect } from '@playwright/test';

export class DesktopTable {
    readonly root: Locator;

    constructor(private page: Page, section: string, service: string) {
        this.root = page.locator(`#${section}-${service}-table-container`);
    }

    rows(): Locator { return this.root.locator('.l8-table tbody tr[data-row-index]'); }
    emptyState(): Locator { return this.root.locator('.l8-empty-state'); }
    addButton(): Locator { return this.root.locator('.l8-btn-primary').first(); }

    /**
     * Waits for rows or an explicit empty state. A container that stays blank
     * means the view threw before rendering; an error text is reported as is.
     */
    async waitForResolved(timeout = 20_000): Promise<'rows' | 'empty'> {
        let state = 'pending';
        await expect.poll(async () => {
            if (await this.rows().count()) return (state = 'rows');
            if (await this.emptyState().count()) return (state = 'empty');
            const text = (await this.root.innerText().catch(() => '')).trim();
            if (text && !(await this.root.locator('.l8-table').count())) return (state = 'error: ' + text);
            return 'pending';
        }, { timeout, message: `${await this.root.getAttribute('id')} never rendered rows, an empty state or an error` })
            .not.toBe('pending');
        if (state.startsWith('error')) throw new Error(`${await this.root.getAttribute('id')} rendered ${state}`);
        return state as 'rows' | 'empty';
    }

    /** Types into a column filter and waits for the refetch. */
    async filterBy(column: string, value: string): Promise<void> {
        const input = this.root.locator(`.l8-filter-input[data-column="${column}"]`);
        const settled = this.page.waitForResponse((r) => r.url().includes('body=') && r.ok(), { timeout: 15_000 }).catch(() => null);
        await input.fill(value);
        await settled;
        await this.page.waitForTimeout(300);
    }

    /** The row showing text in any cell. */
    rowWith(text: string): Locator {
        return this.rows().filter({ hasText: text });
    }

    /** The row whose action buttons carry this record ID. */
    rowById(id: string): Locator {
        return this.rows().filter({ has: this.page.locator(`[data-action][data-id="${id}"]`) });
    }
}
