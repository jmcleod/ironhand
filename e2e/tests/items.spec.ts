import { test, expect } from '@playwright/test';
import {
  register,
  createVault,
  addLoginItem,
  addNoteItem,
  addCardItem,
  uniquePassphrase,
} from '../helpers';

test.describe('Item Management', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('add a login item', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Login Items');

    await addLoginItem(page, 'GitHub', 'octocat', 's3cr3t', 'https://github.com');

    // Verify item appears in the vault list.
    await expect(page.getByRole('main').getByRole('heading', { name: 'GitHub' })).toBeVisible();
  });

  test('add a secure note', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Notes');

    await addNoteItem(page, 'Secret Plan', 'This is a secure note with important information.');

    // Verify item appears.
    await expect(page.getByRole('main').getByRole('heading', { name: 'Secret Plan' })).toBeVisible();
  });

  test('add a card item', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Cards');

    await addCardItem(page, 'My Visa', 'John Doe', '4111111111111111', '12/28', '123');

    // Verify item appears.
    await expect(page.getByRole('main').getByRole('heading', { name: 'My Visa' })).toBeVisible();
  });

  test('open item editor', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Lightbox Test');
    await addLoginItem(page, 'TestSite', 'admin', 'password123', 'https://test.com');

    // Click the item edit control.
    await page.getByTitle('Edit').click();

    // Verify editor dialog opens with item details.
    await expect(page.getByRole('dialog')).toBeVisible();
    await expect(page.getByRole('dialog').getByRole('heading', { name: 'Edit Login' })).toBeVisible();
    await expect(page.getByRole('dialog').locator('input').first()).toHaveValue('TestSite');
  });

  test('add multiple items to a vault', async ({ page }) => {
    const passphrase = uniquePassphrase();
    await register(page, passphrase);
    await createVault(page, 'Multi-Item Vault');

    await addLoginItem(page, 'Site One', 'user1', 'pass1');
    await addLoginItem(page, 'Site Two', 'user2', 'pass2');
    await addNoteItem(page, 'My Note', 'Some secret content');

    // Verify all items are visible.
    await expect(page.getByRole('main').getByRole('heading', { name: 'Site One' })).toBeVisible();
    await expect(page.getByRole('main').getByRole('heading', { name: 'Site Two' })).toBeVisible();
    await expect(page.getByRole('main').getByRole('heading', { name: 'My Note' })).toBeVisible();
  });
});
