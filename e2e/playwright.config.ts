// The l8tunnel browser suite, run against the KIND deployment
// (k8s/kind-start.sh). Desktop drives app.html; mobile drives the real
// mobile bundle at m/app.html on a phone profile, never a narrow desktop.
import { defineConfig, devices } from '@playwright/test';
import { ENV } from './fixtures/env';

export default defineConfig({
    testDir: './tests',
    outputDir: './test-results',
    // Builds the agent binary and installs a throwaway tunnel certificate
    // once, for the specs that run a real agent.
    globalSetup: require.resolve('./fixtures/global-setup'),
    timeout: 90_000,
    expect: { timeout: 20_000 },
    // One web pod and one backend: keep the load at what they serve, so a
    // timeout means a bug, not a queue.
    fullyParallel: true,
    workers: 2,
    // A failure right after a pod restart is usually the cluster settling;
    // one retry separates that from a real bug.
    retries: 1,
    forbidOnly: !!process.env.CI,
    reporter: [['list'], ['html', { open: 'never' }]],
    use: {
        baseURL: ENV.baseURL,
        ignoreHTTPSErrors: true, // KIND's web server is self-signed
        actionTimeout: 15_000,
        navigationTimeout: 30_000,
        trace: 'retain-on-failure',
        screenshot: 'only-on-failure'
    },
    projects: [
        { name: 'desktop', testDir: './tests/desktop', use: { ...devices['Desktop Chrome'], viewport: { width: 1500, height: 950 } } },
        { name: 'mobile', testDir: './tests/mobile', use: { ...devices['Pixel 7'] } }
    ]
});
