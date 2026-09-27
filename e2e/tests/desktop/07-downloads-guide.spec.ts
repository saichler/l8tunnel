// Dashboard: the agent downloads (each with its own token) and the guide.
import { execFileSync } from 'child_process';
import * as fs from 'fs';
import * as os from 'os';
import * as path from 'path';
import { test, expect, assertNoPageErrors } from '../../fixtures/test';
import { AREA, quietly } from '../../fixtures/api';
import { ENV } from '../../fixtures/env';

for (const pkg of [
    { key: 'linux', button: /Linux/, prefix: 'pkg-linux-', expose: 'ssh+https', types: [2, 4] },
    { key: 'mac', button: /macOS/, prefix: 'pkg-mac-', expose: null, types: [2] }
]) {
    test(`the ${pkg.key} download carries its own token and the cluster's domain`, async ({ app, api, capture }) => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'l8t-dl-'));
        let tokenId = '';
        try {
            const button = app.locator('.tun-download-btn', { hasText: pkg.button });
            await expect(button).toBeVisible();
            const [download] = await Promise.all([app.waitForEvent('download'), button.click()]);
            const file = path.join(dir, download.suggestedFilename());
            await download.saveAs(file);
            execFileSync('tar', ['xzf', file, '-C', dir]);

            const top = fs.readdirSync(dir).find((f) => f.startsWith('l8tunnel-agent-download-'));
            expect(top, 'the package has no top directory').toBeTruthy();
            const root = path.join(dir, top!);
            const token = fs.readFileSync(path.join(root, 'TOKEN'), 'utf8').trim();
            expect(token).toMatch(/^l8t_[0-9a-f]+_/);
            expect(fs.statSync(path.join(root, 'TOKEN')).mode & 0o777).toBe(0o600);
            expect(fs.readFileSync(path.join(root, 'DOMAIN'), 'utf8').trim()).toBe(ENV.tunnelBase);
            if (pkg.expose) expect(fs.readFileSync(path.join(root, 'EXPOSE'), 'utf8').trim()).toBe(pkg.expose);
            expect(fs.statSync(path.join(root, 'install.sh')).mode & 0o111).not.toBe(0);
            expect(fs.statSync(path.join(root, 'bin', 'l8tunnel-agent')).mode & 0o111).not.toBe(0);

            // The token in the file was issued for this download, with the package's types.
            const id = token.split('_')[1];
            const rows = await api.query(AREA.access, 'TunToken', `select * from TunToken where tokenId=${id}`);
            const rec = rows.find((r) => r.tokenId === id);
            expect(rec, 'the token in the package was not issued').toBeTruthy();
            tokenId = rec.tokenId;
            expect(rec.name.startsWith(pkg.prefix)).toBe(true);
            expect([...(rec.policy?.types || [])].map((t: string | number) => typeof t === 'number' ? t :
                ({ TUN_TUNNEL_TYPE_SSH: 2, TUN_TUNNEL_TYPE_TLS: 4 } as Record<string, number>)[t])).toEqual(pkg.types);
            await expect(app.locator('.layer8d-notification-container').filter({ hasText: rec.name }).first()).toBeVisible();
            assertNoPageErrors(capture);
        } finally {
            if (tokenId) await quietly(`token ${tokenId}`, () => api.revokeToken(tokenId));
            fs.rmSync(dir, { recursive: true, force: true });
        }
    });
}

test('the guide opens, with its topics and the cluster\'s domain', async ({ app, capture }) => {
    const guide = app.locator('details.tun-guide');
    await expect(guide).toBeVisible();
    await expect(guide).not.toHaveAttribute('open', /.*/);
    await guide.locator('> summary').click();
    const topics = guide.locator('details.tun-guide-topic');
    expect(await topics.count()).toBeGreaterThanOrEqual(8);
    const reach = topics.filter({ hasText: 'Reach a machine' });
    await reach.locator('> summary').click();
    await expect(reach.locator('.tun-guide-code').first()).toContainText(`<user>@${ENV.tunnelBase}`);
    assertNoPageErrors(capture);
});
