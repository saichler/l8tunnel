// The l8ui login page (l8ui/login/), driven through its real form.
import { Page, Locator, expect } from '@playwright/test';
import { ENV } from '../fixtures/env';

export class LoginPage {
    constructor(private page: Page) {}

    username(): Locator { return this.page.locator('#username, [name="username"]').first(); }
    password(): Locator { return this.page.locator('#password, [name="password"]').first(); }
    submit(): Locator { return this.page.locator('button[type="submit"], .login-btn').first(); }
    error(): Locator { return this.page.locator('.login-error, #login-error, .error-message, .error').first(); }

    async goto(): Promise<void> {
        await this.page.goto(ENV.loginShell);
        await expect(this.username()).toBeVisible();
    }

    async login(user: string, pass: string): Promise<void> {
        await this.username().fill(user);
        await this.password().fill(pass);
        await this.submit().click();
    }
}
