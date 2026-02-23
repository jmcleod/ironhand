import { test, expect } from '@playwright/test';
import { register, login, lock, uniquePassphrase } from '../helpers';

test.describe('Authentication', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('register a new account', async ({ page }) => {
    const passphrase = uniquePassphrase();

    // Click register link and wait for page transition.
    await page.getByRole('button', { name: 'Need an account? Register' }).click();
    await expect(page.getByRole('heading', { name: 'Register', level: 1 })).toBeVisible();

    // Fill and submit registration form.
    await page.getByPlaceholder('Passphrase', { exact: true }).fill(passphrase);
    await page.getByPlaceholder('Confirm passphrase').fill(passphrase);

    // Click Register and wait for the 201 API response.
    const responsePromise = page.waitForResponse(
      (resp) => resp.url().includes('/auth/register') && resp.status() === 201,
    );
    await page.getByRole('button', { name: 'Register', exact: true }).click();
    await responsePromise;

    // Verify secret key is displayed (the code element only appears in the success view).
    await expect(page.locator('code')).toBeVisible({ timeout: 15_000 });
    const secretKey = await page.locator('code').textContent();
    expect(secretKey).toBeTruthy();
    expect(secretKey!.length).toBeGreaterThan(10);

    // Acknowledge and continue.
    await page.getByLabel('I have securely saved my secret key.').click();
    await page.getByRole('button', { name: 'Continue to Dashboard' }).click();

    // Verify we're on the dashboard.
    await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible({
      timeout: 10_000,
    });
  });

  test('lock and unlock', async ({ page }) => {
    const passphrase = uniquePassphrase();
    const creds = await register(page, passphrase);

    // Lock the session.
    await lock(page);

    // Login page should be visible.
    await expect(page.getByRole('heading', { name: 'Login', level: 1 })).toBeVisible();

    // Log back in.
    await login(page, creds);

    // Verify we're back on the dashboard.
    await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible();
  });

  test('wrong credentials are rejected', async ({ page }) => {
    const passphrase = uniquePassphrase();
    const creds = await register(page, passphrase);

    // Lock the session.
    await lock(page);

    // Attempt login with wrong passphrase.
    await page.getByPlaceholder('Secret key').fill(creds.secretKey);
    await page.getByPlaceholder('Passphrase', { exact: true }).fill('wrong-passphrase-here');
    await page.getByRole('button', { name: 'Login', exact: true }).click();

    // Verify error toast appears (use exact match to avoid aria-live duplicate).
    await expect(page.getByText('Login Failed', { exact: true })).toBeVisible({ timeout: 10_000 });
  });

  test('remember secret key for session', async ({ page }) => {
    const passphrase = uniquePassphrase();
    const creds = await register(page, passphrase);

    // Lock the session.
    await lock(page);

    // Check "Remember secret key" and login.
    await page.getByPlaceholder('Secret key').fill(creds.secretKey);
    await page.getByPlaceholder('Passphrase', { exact: true }).fill(creds.passphrase);
    await page.getByLabel('Remember secret key for this session').click();
    await page.getByRole('button', { name: 'Login', exact: true }).click();

    // Wait for dashboard.
    await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible({
      timeout: 15_000,
    });

    // Lock again.
    await lock(page);

    // Verify the secret key field is pre-filled.
    const secretKeyInput = page.getByPlaceholder('Secret key');
    await expect(secretKeyInput).toHaveValue(creds.secretKey);
  });
});
