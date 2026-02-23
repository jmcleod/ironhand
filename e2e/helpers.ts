import { type Page, expect } from '@playwright/test';

/** Generate a unique passphrase for test isolation. */
export function uniquePassphrase(): string {
  return `TestPass_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
}

export interface Credentials {
  secretKey: string;
  passphrase: string;
}

/**
 * Register a new account. Starts from the login page (default landing).
 * Returns the secret key and passphrase for subsequent login.
 */
export async function register(page: Page, passphrase: string): Promise<Credentials> {
  // Click the "Need an account? Register" button on the Login page.
  await page.getByRole('button', { name: 'Need an account? Register' }).click();

  // Wait for the Register page heading to appear before filling fields.
  // This prevents a race where fill() targets the Login page's passphrase
  // field before React re-renders the Register page.
  await expect(page.getByRole('heading', { name: 'Register', level: 1 })).toBeVisible();

  // Fill registration form.
  await page.getByPlaceholder('Passphrase', { exact: true }).fill(passphrase);
  await page.getByPlaceholder('Confirm passphrase').fill(passphrase);

  // Click Register and wait for the 201 API response before checking the UI.
  // This anchors on the network response to avoid any React timing issues.
  const responsePromise = page.waitForResponse(
    (resp) => resp.url().includes('/auth/register') && resp.status() === 201,
  );
  await page.getByRole('button', { name: 'Register', exact: true }).click();
  await responsePromise;

  // Wait for the secret key <code> element (only rendered in the success view).
  await expect(page.locator('code')).toBeVisible({ timeout: 15_000 });

  // Extract secret key from the <code> element.
  const secretKey = await page.locator('code').textContent();
  if (!secretKey) throw new Error('Secret key not found on registration success page');

  // Acknowledge saving the key.
  await page.getByLabel('I have securely saved my secret key.').click();

  // Continue to dashboard.
  await page.getByRole('button', { name: 'Continue to Dashboard' }).click();

  // Wait for dashboard to load.
  await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible({
    timeout: 10_000,
  });

  return { secretKey, passphrase };
}

/**
 * Log in with existing credentials. Assumes we're on the login page.
 */
export async function login(page: Page, credentials: Credentials): Promise<void> {
  // Wait for the login form to be ready.
  await expect(page.getByRole('heading', { name: 'Login', level: 1 })).toBeVisible();

  await page.getByPlaceholder('Secret key').fill(credentials.secretKey);
  await page.getByPlaceholder('Passphrase', { exact: true }).fill(credentials.passphrase);
  await page.getByRole('button', { name: 'Login', exact: true }).click();

  // Wait for dashboard.
  await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible({
    timeout: 15_000,
  });
}

/**
 * Lock the current session (click the Lock button on the dashboard).
 */
export async function lock(page: Page): Promise<void> {
  await page.getByRole('button', { name: 'Lock' }).click();

  // Wait for login page to appear.
  await expect(page.getByRole('heading', { name: 'Login', level: 1 })).toBeVisible();
}

/**
 * Create a new vault from the dashboard.
 * After creation, navigates into the vault detail view.
 */
export async function createVault(
  page: Page,
  name: string,
  description?: string,
): Promise<void> {
  await page.getByRole('button', { name: 'New Vault' }).click();

  // Wait for the create vault dialog to open.
  await expect(page.getByRole('dialog')).toBeVisible();

  await page.getByPlaceholder('My Secrets').fill(name);
  if (description) {
    await page.getByPlaceholder('Optional description').fill(description);
  }
  await page.getByRole('button', { name: 'Create Vault' }).click();

  // Wait for dialog to close (vault created, dashboard refreshes).
  await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 10_000 });

  // The UI stays on the dashboard after creation — click the vault card to open it.
  await page.getByText(name, { exact: true }).click();

  // Wait for vault detail view to appear with the name as h1.
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible({
    timeout: 10_000,
  });
}

/**
 * Open an existing vault by clicking its card on the dashboard.
 */
export async function openVault(page: Page, name: string): Promise<void> {
  await page.getByText(name, { exact: true }).click();

  // Wait for vault detail view.
  await expect(page.getByRole('heading', { name, level: 1 })).toBeVisible();
}

/**
 * Navigate back to the dashboard from a vault detail view.
 */
export async function goBackToDashboard(page: Page): Promise<void> {
  // The back button is the first button in the vault header area.
  // Use a narrow locator: the button that contains an SVG (the ArrowLeft icon).
  await page.locator('button:has(svg.lucide-arrow-left)').click();

  // Wait for dashboard.
  await expect(page.getByRole('heading', { name: 'Ironhand', level: 1 })).toBeVisible();
}

/**
 * Add a login item to the currently open vault.
 */
export async function addLoginItem(
  page: Page,
  name: string,
  username: string,
  password: string,
  url?: string,
): Promise<void> {
  // Click "Add Item" button in the vault header (not the empty-state button).
  await page.getByRole('banner').getByRole('button', { name: 'Add Item' }).click();

  // Wait for dialog to open.
  await expect(page.getByRole('dialog')).toBeVisible();

  // Fill item form (default type is already "Login").
  await page.getByPlaceholder('Item name').fill(name);
  await page.getByPlaceholder('username or email').fill(username);
  await page.getByPlaceholder('password').fill(password);
  if (url) {
    await page.getByPlaceholder('https://example.com').fill(url);
  }

  // Click the "Add Item" button inside the dialog (submit).
  await page.getByRole('dialog').getByRole('button', { name: 'Add Item' }).click();

  // Wait for dialog to close and item to appear in the vault list.
  await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('button', { name })).toBeVisible({ timeout: 10_000 });
}

/**
 * Add a secure note item to the currently open vault.
 */
export async function addNoteItem(
  page: Page,
  name: string,
  content: string,
): Promise<void> {
  await page.getByRole('banner').getByRole('button', { name: 'Add Item' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();

  await page.getByPlaceholder('Item name').fill(name);

  // Change type to Secure Note via the Radix select.
  await page.locator('[role="combobox"]').click();
  await page.getByRole('option', { name: 'Secure Note' }).click();

  await page.getByPlaceholder('Enter your secure note...').fill(content);

  await page.getByRole('dialog').getByRole('button', { name: 'Add Item' }).click();

  // Wait for dialog to close and item to appear.
  await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('button', { name })).toBeVisible({ timeout: 10_000 });
}

/**
 * Add a card item to the currently open vault.
 */
export async function addCardItem(
  page: Page,
  name: string,
  cardholder: string,
  cardNumber: string,
  expiry: string,
  cvv: string,
): Promise<void> {
  await page.getByRole('banner').getByRole('button', { name: 'Add Item' }).click();
  await expect(page.getByRole('dialog')).toBeVisible();

  await page.getByPlaceholder('Item name').fill(name);

  // Change type to Card.
  await page.locator('[role="combobox"]').click();
  await page.getByRole('option', { name: 'Card' }).click();

  await page.getByPlaceholder('Name on card').fill(cardholder);
  await page.getByPlaceholder('Card number').fill(cardNumber);
  await page.getByPlaceholder('MM/YY').fill(expiry);
  await page.getByPlaceholder('CVV').fill(cvv);

  await page.getByRole('dialog').getByRole('button', { name: 'Add Item' }).click();

  // Wait for dialog to close and item to appear.
  await expect(page.getByRole('dialog')).not.toBeVisible({ timeout: 10_000 });
  await expect(page.getByRole('button', { name })).toBeVisible({ timeout: 10_000 });
}

/**
 * Register and set up a vault with optional items. Returns credentials.
 * Convenience wrapper for tests that need a populated vault.
 */
export async function registerAndCreateVault(
  page: Page,
  vaultName: string,
): Promise<Credentials> {
  const passphrase = uniquePassphrase();
  const creds = await register(page, passphrase);
  await createVault(page, vaultName);
  return creds;
}
