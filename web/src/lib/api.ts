import { AuditEntry, CAInfo, HistoryEntry, IssueCertResult, RenewCertResult, VaultSummary } from '@/types/vault';

const API_BASE = '/api/v1';

export type ApiError = {
  status: number;
  message: string;
};

async function readError(resp: Response): Promise<never> {
  let message = `Request failed (${resp.status})`;
  try {
    const data = await resp.json();
    if (typeof data?.error === 'string') {
      message = data.error;
    }
  } catch {
    // ignore parse errors
  }
  throw { status: resp.status, message } as ApiError;
}

function getCsrfToken(): string | null {
  const match = document.cookie.match(/(?:^|;\s*)ironhand_csrf=([^;]*)/);
  return match ? decodeURIComponent(match[1]) : null;
}

async function request(path: string, init: RequestInit = {}) {
  // Build a clean headers map from caller-provided headers, then layer on
  // the CSRF token for mutating requests so it is never accidentally lost.
  const headers: Record<string, string> = {};

  // Copy caller-supplied headers into our plain object.
  if (init.headers) {
    if (init.headers instanceof Headers) {
      init.headers.forEach((v, k) => {
        headers[k] = v;
      });
    } else if (Array.isArray(init.headers)) {
      for (const [k, v] of init.headers) {
        headers[k] = v;
      }
    } else {
      Object.assign(headers, init.headers);
    }
  }

  // Attach CSRF token for mutating requests (POST/PUT/DELETE).
  const method = (init.method ?? 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const token = getCsrfToken();
    if (token) {
      headers['X-CSRF-Token'] = token;
    }
  }

  const resp = await fetch(`${API_BASE}${path}`, {
    method: init.method,
    body: init.body,
    credentials: 'include',
    headers,
  });
  if (!resp.ok) {
    return readError(resp);
  }
  return resp;
}

export async function register(passphrase: string): Promise<{ secret_key: string }> {
  const resp = await request('/auth/register', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ passphrase }),
  });
  return resp.json();
}

export async function login(passphrase: string, secretKey: string, totpCode?: string): Promise<void> {
  await request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      passphrase,
      secret_key: secretKey,
      totp_code: totpCode ?? '',
    }),
  });
}

export async function logout(): Promise<void> {
  await request('/auth/logout', { method: 'POST' });
}

export async function twoFactorStatus(): Promise<{ enabled: boolean }> {
  const resp = await request('/auth/2fa');
  return (await resp.json()) as { enabled: boolean };
}

export async function setupTwoFactor(): Promise<{ secret: string; otpauth_url: string; expires_at: string }> {
  const resp = await request('/auth/2fa/setup', { method: 'POST' });
  return (await resp.json()) as { secret: string; otpauth_url: string; expires_at: string };
}

export async function enableTwoFactor(code: string): Promise<{ enabled: boolean }> {
  const resp = await request('/auth/2fa/enable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  return (await resp.json()) as { enabled: boolean };
}

export async function listVaults(): Promise<VaultSummary[]> {
  const resp = await request('/vaults');
  const data = (await resp.json()) as { vaults: VaultSummary[] };
  return data.vaults ?? [];
}

export async function createVault(input: { name?: string; description?: string }) {
  const resp = await request('/vaults', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      name: input.name ?? '',
      description: input.description ?? '',
    }),
  });
  return resp.json() as Promise<{
    vault_id: string;
    member_id: string;
    epoch: number;
  }>;
}

export async function deleteVault(vaultID: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}`, { method: 'DELETE' });
}

export interface ItemSummary {
  item_id: string;
  name?: string;
  type?: string;
}

export async function listItems(vaultID: string): Promise<ItemSummary[]> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/items`);
  const data = (await resp.json()) as { items: ItemSummary[] };
  return data.items ?? [];
}

export async function getItem(vaultID: string, itemID: string): Promise<Record<string, string>> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`);
  const data = (await resp.json()) as { fields: Record<string, string> };
  return data.fields;
}

export async function putItem(vaultID: string, itemID: string, fields: Record<string, string>): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
}

export async function updateItem(vaultID: string, itemID: string, fields: Record<string, string>): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ fields }),
  });
}

export async function deleteItem(vaultID: string, itemID: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`, { method: 'DELETE' });
}

export async function addMember(
  vaultID: string,
  req: { memberID: string; pubKey: string; role: 'owner' | 'writer' | 'reader' },
): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/members`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      member_id: req.memberID,
      pub_key: req.pubKey,
      role: req.role,
    }),
  });
}

export async function revokeMember(vaultID: string, memberID: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/members/${encodeURIComponent(memberID)}`, { method: 'DELETE' });
}

export async function getItemHistory(vaultID: string, itemID: string): Promise<HistoryEntry[]> {
  const resp = await request(
    `/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}/history`,
  );
  const data = (await resp.json()) as { history: HistoryEntry[] };
  return data.history ?? [];
}

export async function getHistoryVersion(
  vaultID: string,
  itemID: string,
  version: number,
): Promise<Record<string, string>> {
  const resp = await request(
    `/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}/history/${version}`,
  );
  const data = (await resp.json()) as { fields: Record<string, string> };
  return data.fields;
}

export async function listAuditLogs(vaultID: string, itemID?: string): Promise<AuditEntry[]> {
  const params = new URLSearchParams();
  if (itemID) params.set('item_id', itemID);
  const qs = params.toString();
  const path = `/vaults/${encodeURIComponent(vaultID)}/audit${qs ? `?${qs}` : ''}`;
  const resp = await request(path);
  const data = (await resp.json()) as { entries: AuditEntry[] };
  return data.entries ?? [];
}

export async function exportVault(vaultID: string, passphrase: string): Promise<Blob> {
  const csrfHeaders: Record<string, string> = { 'Content-Type': 'application/json' };
  const csrf = getCsrfToken();
  if (csrf) csrfHeaders['X-CSRF-Token'] = csrf;
  const resp = await fetch(`${API_BASE}/vaults/${encodeURIComponent(vaultID)}/export`, {
    method: 'POST',
    credentials: 'include',
    headers: csrfHeaders,
    body: JSON.stringify({ passphrase }),
  });
  if (!resp.ok) {
    return readError(resp);
  }
  return resp.blob();
}

export async function importVault(
  vaultID: string,
  file: File,
  passphrase: string,
): Promise<{ imported_count: number }> {
  const formData = new FormData();
  formData.append('file', file);
  formData.append('passphrase', passphrase);

  const importHeaders: Record<string, string> = {};
  const csrf = getCsrfToken();
  if (csrf) importHeaders['X-CSRF-Token'] = csrf;

  const resp = await fetch(`${API_BASE}/vaults/${encodeURIComponent(vaultID)}/import`, {
    method: 'POST',
    credentials: 'include',
    headers: importHeaders,
    body: formData,
  });
  if (!resp.ok) {
    return readError(resp);
  }
  return resp.json() as Promise<{ imported_count: number }>;
}

// ---------------------------------------------------------------------------
// PKI / Certificate Authority
// ---------------------------------------------------------------------------

export interface InitCARequestParams {
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  province?: string;
  locality?: string;
  validity_years?: number;
  is_intermediate?: boolean;
}

export async function initCA(
  vaultID: string,
  req: InitCARequestParams,
): Promise<{ subject: string }> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/pki/init`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  return resp.json() as Promise<{ subject: string }>;
}

export async function getCAInfo(vaultID: string): Promise<CAInfo | null> {
  try {
    const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/pki/info`);
    return (await resp.json()) as CAInfo;
  } catch (err) {
    if ((err as ApiError).status === 404) return null;
    throw err;
  }
}

export async function getCACert(vaultID: string): Promise<string> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/pki/ca.pem`);
  return resp.text();
}

export interface IssueCertRequestParams {
  common_name: string;
  organization?: string;
  org_unit?: string;
  country?: string;
  validity_days?: number;
  key_usages?: string[];
  ext_key_usages?: string[];
  dns_names?: string[];
  ip_addresses?: string[];
  email_addresses?: string[];
}

export async function issueCert(
  vaultID: string,
  req: IssueCertRequestParams,
): Promise<IssueCertResult> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/pki/issue`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(req),
  });
  return resp.json() as Promise<IssueCertResult>;
}

export async function revokeCert(
  vaultID: string,
  itemID: string,
  reason?: string,
): Promise<void> {
  await request(
    `/vaults/${encodeURIComponent(vaultID)}/pki/items/${encodeURIComponent(itemID)}/revoke`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ reason: reason ?? 'unspecified' }),
    },
  );
}

export async function renewCert(
  vaultID: string,
  itemID: string,
  validityDays?: number,
): Promise<RenewCertResult> {
  const resp = await request(
    `/vaults/${encodeURIComponent(vaultID)}/pki/items/${encodeURIComponent(itemID)}/renew`,
    {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ validity_days: validityDays ?? 365 }),
    },
  );
  return resp.json() as Promise<RenewCertResult>;
}

export async function getCRL(vaultID: string): Promise<string> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/pki/crl.pem`);
  return resp.text();
}

// ---------------------------------------------------------------------------
// WebAuthn / Passkey
// ---------------------------------------------------------------------------

export async function webauthnStatus(): Promise<{ enabled: boolean; credential_count: number }> {
  const resp = await request('/auth/webauthn/status');
  return (await resp.json()) as { enabled: boolean; credential_count: number };
}

export async function beginWebAuthnRegistration(): Promise<unknown> {
  const resp = await request('/auth/webauthn/register/begin', { method: 'POST' });
  return resp.json();
}

export async function finishWebAuthnRegistration(credential: unknown): Promise<{ credential_id: string }> {
  const resp = await request('/auth/webauthn/register/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
  return (await resp.json()) as { credential_id: string };
}

export async function beginWebAuthnLogin(
  secretKey: string,
  passphrase: string,
): Promise<unknown> {
  const resp = await request('/auth/webauthn/login/begin', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ secret_key: secretKey, passphrase }),
  });
  return resp.json();
}

export async function finishWebAuthnLogin(credential: unknown): Promise<void> {
  await request('/auth/webauthn/login/finish', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credential),
  });
}
