import { VaultSummary } from '@/types/vault';

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

async function request(path: string, init: RequestInit = {}) {
  const resp = await fetch(`${API_BASE}${path}`, {
    credentials: 'include',
    ...init,
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

export async function login(passphrase: string, secretKey: string): Promise<void> {
  await request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      passphrase,
      secret_key: secretKey,
    }),
  });
}

export async function logout(): Promise<void> {
  await request('/auth/logout', { method: 'POST' });
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

export async function listItems(vaultID: string): Promise<string[]> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/items`);
  const data = (await resp.json()) as { items: string[] };
  return data.items ?? [];
}

export async function getItem(vaultID: string, itemID: string): Promise<string> {
  const resp = await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`);
  const data = (await resp.json()) as { data: string };
  return data.data;
}

export async function putItem(vaultID: string, itemID: string, data: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, content_type: 'application/json' }),
  });
}

export async function updateItem(vaultID: string, itemID: string, data: string): Promise<void> {
  await request(`/vaults/${encodeURIComponent(vaultID)}/items/${encodeURIComponent(itemID)}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ data, content_type: 'application/json' }),
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
