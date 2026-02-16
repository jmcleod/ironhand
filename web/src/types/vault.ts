export type ItemType = 'login' | 'note' | 'card' | 'custom';

export interface VaultItem {
  id: string;
  fields: Record<string, string>;
}

export interface Vault {
  id: string;
  name: string;
  description: string;
  items: VaultItem[];
  sharedWith: string[];
  createdAt: string;
  updatedAt: string;
  epoch: number;
  itemCount: number;
}

// Conventional metadata field names (prefixed with _)
export const FIELD_NAME = '_name';
export const FIELD_TYPE = '_type';
export const FIELD_CREATED = '_created';
export const FIELD_UPDATED = '_updated';

export function itemName(item: VaultItem): string {
  return item.fields[FIELD_NAME] || item.id;
}

export function itemType(item: VaultItem): ItemType {
  return (item.fields[FIELD_TYPE] as ItemType) || 'custom';
}

export function itemCreatedAt(item: VaultItem): string {
  return item.fields[FIELD_CREATED] || '';
}

export function itemUpdatedAt(item: VaultItem): string {
  return item.fields[FIELD_UPDATED] || '';
}

// Returns only the user-facing fields (excludes _ prefixed metadata)
export function userFields(item: VaultItem): Record<string, string> {
  const result: Record<string, string> = {};
  for (const [k, v] of Object.entries(item.fields)) {
    if (!k.startsWith('_')) {
      result[k] = v;
    }
  }
  return result;
}

// Field names that should be masked by default
export const SENSITIVE_FIELDS = new Set(['password', 'cvv', 'card_number', 'totp']);

export interface VaultProfile {
  vaultID: string;
  credentials: string;
  passphrase: string;
  secretKey?: string;
  memberID?: string;
  label?: string;
}

export interface SessionState {
  profiles: VaultProfile[];
  activeVaultID?: string;
}

export interface VaultSummary {
  vault_id: string;
  name?: string;
  description?: string;
  epoch: number;
  item_count: number;
}

export interface HistoryEntry {
  version: number;
  updated_at: string;
  updated_by: string;
}

export interface AuditEntry {
  id: string;
  item_id: string;
  action: 'item_accessed' | 'item_created' | 'item_updated' | 'item_deleted';
  member_id: string;
  created_at: string;
}
