import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './e2e/tests',
  globalSetup: './e2e/global-setup.ts',
  globalTeardown: './e2e/global-teardown.ts',
  timeout: 30_000,
  expect: {
    timeout: 10_000,
  },
  retries: 0,
  workers: 1,
  use: {
    baseURL: 'https://localhost:9443',
    ignoreHTTPSErrors: true,
    screenshot: 'only-on-failure',
    trace: 'retain-on-failure',
  },
  projects: [
    {
      name: 'chromium',
      use: { browserName: 'chromium' },
    },
  ],
  reporter: [['html', { open: 'never' }]],
});
