import { test, expect } from '@playwright/test';
import {
  addLoginItem,
  createVault,
  expectConsoleReady,
  goBackToDashboard,
  register,
  uniquePassphrase,
} from '../helpers';

test.describe('Security console', () => {
  test.beforeEach(async ({ page }) => {
    await page.goto('/');
  });

  test('navigates through primary console sections', async ({ page }) => {
    await register(page, uniquePassphrase());
    await createVault(page, 'Console Coverage Vault', 'E2E coverage vault');
    await goBackToDashboard(page);

    const topNav = page.getByRole('banner');

    await topNav.getByRole('button', { name: 'Overview' }).click();
    await expect(page.getByText('Security Posture')).toBeVisible();
    await expect(page.getByText('Vault Access Graph')).toBeVisible();

    await topNav.getByRole('button', { name: 'Members' }).click();
    await expect(page.getByText('Member Role Matrix')).toBeVisible();

    await topNav.getByRole('button', { name: 'Access' }).click();
    await expect(page.getByRole('heading', { name: 'Access Requests' })).toBeVisible();
    await expect(page.getByText('Revocation Watchlist')).toBeVisible();

    await topNav.getByRole('button', { name: 'CA', exact: true }).click();
    await expect(page.getByText('Authority State')).toBeVisible();
    await expect(page.getByText('Certificate Inventory')).toBeVisible();

    await topNav.getByRole('button', { name: 'MPC' }).click();
    await expect(page.getByText('MPC Readiness')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'MPC Signing Inbox' })).toBeVisible();

    await topNav.getByRole('button', { name: 'Audit' }).click();
    await expect(page.getByText('Hash Chain')).toBeVisible();
    await expect(page.getByRole('heading', { name: 'Audit Log' })).toBeVisible();

    await topNav.getByRole('button', { name: 'Settings' }).click();
    await expect(page.getByText('Account Security')).toBeVisible();
    await expect(page.getByText('Tools')).toBeVisible();
  });

  test('opens commands and jumps to vault content', async ({ page }) => {
    await register(page, uniquePassphrase());
    await createVault(page, 'Command Vault');
    await addLoginItem(page, 'Console Login', 'console-user', 'console-pass');
    await goBackToDashboard(page);

    await page.keyboard.press('Control+K');
    await expect(page.getByPlaceholder('Search vaults, secrets, and commands...')).toBeVisible();
    await page.getByRole('option', { name: /Settings/ }).click();
    await expect(page.getByText('Account Security')).toBeVisible();

    await page.getByRole('button', { name: 'Type a command or search...' }).click();
    await page.getByPlaceholder('Search vaults, secrets, and commands...').fill('Console Login');
    await page.getByRole('option', { name: /Console Login/ }).click();

    await expectConsoleReady(page);
    await expect(page.getByRole('heading', { name: 'Command Vault' })).toBeVisible();
    await expect(page.getByRole('main').getByRole('heading', { name: 'Console Login' })).toBeVisible();
  });
});
