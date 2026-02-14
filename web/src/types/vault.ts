export type ItemType = 'text' | 'image' | 'email';

export interface VaultItem {
  id: string;
  name: string;
  type: ItemType;
  data: string;
  createdAt: string;
  updatedAt: string;
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
