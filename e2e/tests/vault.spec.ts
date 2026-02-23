import { test, expect } from '@playwright/test';
import { register, createVault, openVault, goBackToDashboard, uniquePassphrase } from '../helpers';

test.describe('Vault Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('create a new vault', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create a vault via helper (creates vault, then clicks into detail view).
    await createVault(page, 'Test Vault');

    // Verify vault detail view shows the vault name as h1.
    await expect(page.getByRole('heading', { name: 'Test Vault', level: 1 })).toBeVisible();
  });

  test('navigate back from vault to dashboard', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Navigate Test');

    // Click back button (ArrowLeft icon button — the icon-only ghost button).
    await goBackToDashboard(page);

    // Verify we're back on dashboard.
    await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible();
  });

  test('delete a vault', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Delete Me');

    // Set up dialog handler to accept the confirm prompt.
    page.on('dialog', (dialog) => dialog.accept());

    // Click the delete button (Trash2 icon — the destructive-colored button).
    await page.locator('button.text-destructive').click();

    // Verify we're back on dashboard and vault is gone.
    await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible({
      timeout: 10_000,
    });
    await expect(page.getByText('Delete Me')).not.toBeVisible();
  });

  test('create multiple vaults', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create first vault.
    await createVault(page, 'Vault Alpha');

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Create second vault.
    await createVault(page, 'Vault Beta');

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Verify both vault cards are visible.
    await expect(page.getByText('Vault Alpha')).toBeVisible();
    await expect(page.getByText('Vault Beta')).toBeVisible();
  });
});
