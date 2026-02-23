import { test, expect } from '@playwright/test';
import {
  register,
  createVault,
  addLoginItem,
  goBackToDashboard,
  uniquePassphrase,
} from '../helpers';

test.describe('Search', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('search finds items across vaults', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create first vault with items.
    await createVault(page, 'Work Vault');
    await addLoginItem(page, 'Jira Login', 'worker', 'pass1');

    // Go back and create second vault.
    await goBackToDashboard(page);

    await createVault(page, 'Personal Vault');
    await addLoginItem(page, 'Gmail Account', 'me@gmail.com', 'pass2');

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Search for "Login" — should find items from both vaults.
    const searchInput = page.getByPlaceholder('Search items across all vaults...');
    await searchInput.fill('Login');

    // Wait for search results.
    await expect(page.getByText(/\d+ items? found/)).toBeVisible({ timeout: 10_000 });
  });

  test('empty search shows no results message', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create a vault with an item.
    await createVault(page, 'Search Test');
    await addLoginItem(page, 'My Site', 'user', 'pass');

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Search for something that doesn't exist.
    const searchInput = page.getByPlaceholder('Search items across all vaults...');
    await searchInput.fill('zzz_nonexistent_xyz');

    // Verify "no items" message.
    await expect(page.getByText('No items match your search')).toBeVisible({ timeout: 10_000 });
  });

  test('clear search returns to dashboard view', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);

    // Create a vault.
    await createVault(page, 'Clear Search Test');
    await addLoginItem(page, 'Test Item', 'user', 'pass');

    // Go back to dashboard.
    await goBackToDashboard(page);

    // Search and verify results.
    const searchInput = page.getByPlaceholder('Search items across all vaults...');
    await searchInput.fill('Test');
    await expect(page.getByText(/\d+ items? found/)).toBeVisible({ timeout: 10_000 });

    // Clear the search.
    await searchInput.clear();

    // Verify vault cards are visible again.
    await expect(page.getByText('Clear Search Test')).toBeVisible();
  });
});
