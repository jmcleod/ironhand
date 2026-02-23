import { test, expect } from '@playwright/test';
import {
  register,
  createVault,
  addLoginItem,
  addNoteItem,
  goBackToDashboard,
  uniquePassphrase,
} from '../helpers';

test.describe('Export & Import', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('export vault as backup', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Export Test');
    await addLoginItem(page, 'Test Login', 'user', 'pass');

    // Click Export button.
    await page.getByRole('button', { name: 'Export' }).click();

    // Fill export passphrase.
    await page.getByPlaceholder('Enter a strong passphrase').fill('export-pass-12345');
    await page.getByPlaceholder('Confirm passphrase').fill('export-pass-12345');

    // Listen for the download event.
    const downloadPromise = page.waitForEvent('download');

    // Click Export Backup button.
    await page.getByRole('button', { name: 'Export Backup' }).click();

    // Verify download was triggered.
    const download = await downloadPromise;
    expect(download.suggestedFilename()).toContain('.ironhand-backup');
  });

  test('export and import vault backup', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create source vault with items.
    await createVault(page, 'Source Vault');
    await addLoginItem(page, 'Important Login', 'admin', 'secret123');
    await addNoteItem(page, 'Important Note', 'Do not forget this.');

    // Export the vault.
    await page.getByRole('button', { name: 'Export' }).click();
    const exportPassphrase = 'backup-pass-12345';
    await page.getByPlaceholder('Enter a strong passphrase').fill(exportPassphrase);
    await page.getByPlaceholder('Confirm passphrase').fill(exportPassphrase);

    const downloadPromise = page.waitForEvent('download');
    await page.getByRole('button', { name: 'Export Backup' }).click();
    const download = await downloadPromise;

    // Save the downloaded file to a temp path.
    const backupPath = await download.path();
    expect(backupPath).toBeTruthy();

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Create a new vault to import into.
    await createVault(page, 'Import Target');

    // Click Import button.
    await page.getByRole('button', { name: 'Import' }).click();

    // Upload the backup file.
    const fileInput = page.locator('input[type="file"][accept=".ironhand-backup"]');
    await fileInput.setInputFiles(backupPath!);

    // Enter the backup passphrase.
    await page.getByPlaceholder('Enter the backup passphrase').fill(exportPassphrase);

    // Click Import Backup button.
    await page.getByRole('button', { name: 'Import Backup' }).click();

    // Wait for import to complete — items should appear in the vault.
    await expect(page.getByRole('button', { name: 'Important Login' })).toBeVisible({
      timeout: 15_000,
    });
    await expect(page.getByRole('button', { name: 'Important Note' })).toBeVisible();
  });
});
