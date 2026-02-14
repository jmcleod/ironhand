import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import {
  addMember as apiAddMember,
  createVault as apiCreateVault,
  deleteItem as apiDeleteItem,
  deleteVault as apiDeleteVault,
  getItem as apiGetItem,
  listItems as apiListItems,
  listVaults as apiListVaults,
  login as apiLogin,
  logout as apiLogout,
  putItem as apiPutItem,
  register as apiRegister,
  revokeMember as apiRevokeMember,
  updateItem as apiUpdateItem,
} from '@/lib/api';
import { generateId } from '@/lib/crypto';
import { ItemType, Vault, VaultItem } from '@/types/vault';

interface AccountState {
  vaults: Vault[];
}

interface VaultContextType {
  isEnrolled: boolean;
  isUnlocked: boolean;
  account: AccountState | null;
  enroll: (passphrase: string) => Promise<{ secretKey: string }>;
  unlock: (secretKey: string, passphrase: string) => Promise<boolean>;
  lock: () => Promise<void>;
  refresh: () => Promise<void>;
  createVault: (name: string, description: string) => Promise<void>;
  deleteVault: (vaultId: string) => Promise<void>;
  addItem: (vaultId: string, name: string, type: ItemType, data: string) => Promise<void>;
  removeItem: (vaultId: string, itemId: string) => Promise<void>;
  updateItem: (vaultId: string, itemId: string, updates: Partial<Pick<VaultItem, 'name' | 'type' | 'data'>>) => Promise<void>;
  shareVault: (vaultId: string, memberID: string, pubKey: string, role: 'owner' | 'writer' | 'reader') => Promise<void>;
  revokeMember: (vaultId: string, memberID: string) => Promise<void>;
  getDecryptedData: (data: string) => string;
}

const VaultContext = createContext<VaultContextType | null>(null);

type StoredItemPayload = {
  name: string;
  type: ItemType;
  data: string;
  createdAt: string;
  updatedAt: string;
};

function encodeItemPayload(payload: StoredItemPayload): string {
  return btoa(unescape(encodeURIComponent(JSON.stringify(payload))));
}

function decodeItemPayload(input: string): StoredItemPayload {
  return JSON.parse(decodeURIComponent(escape(atob(input)))) as StoredItemPayload;
}

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [justRegistered, setJustRegistered] = useState(false);

  const refresh = useCallback(async () => {
    const summaries = await apiListVaults();
    const nextVaults: Vault[] = [];
    for (const summary of summaries) {
      const itemIDs = await apiListItems(summary.vault_id).catch(() => []);
      const items: VaultItem[] = [];
      for (const itemID of itemIDs) {
        const raw = await apiGetItem(summary.vault_id, itemID).catch(() => '');
        if (!raw) {
          continue;
        }
        try {
          const payload = decodeItemPayload(raw);
          items.push({
            id: itemID,
            name: payload.name,
            type: payload.type,
            data: payload.data,
            createdAt: payload.createdAt,
            updatedAt: payload.updatedAt,
          });
        } catch {
          items.push({
            id: itemID,
            name: itemID,
            type: 'text',
            data: raw,
            createdAt: new Date().toISOString(),
            updatedAt: new Date().toISOString(),
          });
        }
      }
      nextVaults.push({
        id: summary.vault_id,
        name: summary.name || summary.vault_id,
        description: summary.description || '',
        items,
        sharedWith: [],
        createdAt: '',
        updatedAt: new Date().toISOString(),
        epoch: summary.epoch,
        itemCount: summary.item_count,
      });
    }
    setVaults(nextVaults);
  }, []);

  const enroll = useCallback(async (passphrase: string) => {
    const result = await apiRegister(passphrase);
    setIsUnlocked(true);
    setJustRegistered(true);
    setVaults([]);
    return { secretKey: result.secret_key };
  }, []);

  const unlock = useCallback(
    async (secretKey: string, passphrase: string) => {
      try {
        await apiLogin(passphrase, secretKey);
        setIsUnlocked(true);
        setJustRegistered(false);
        await refresh();
        return true;
      } catch {
        return false;
      }
    },
    [refresh],
  );

  const lock = useCallback(async () => {
    await apiLogout().catch(() => undefined);
    setIsUnlocked(false);
    setVaults([]);
    setJustRegistered(false);
  }, []);

  const createVault = useCallback(
    async (name: string, description: string) => {
      await apiCreateVault({ name, description });
      await refresh();
    },
    [refresh],
  );

  const deleteVault = useCallback(
    async (vaultID: string) => {
      await apiDeleteVault(vaultID);
      await refresh();
    },
    [refresh],
  );

  const addItem = useCallback(
    async (vaultID: string, name: string, type: ItemType, data: string) => {
      const now = new Date().toISOString();
      const itemID = generateId();
      const payload = encodeItemPayload({ name, type, data, createdAt: now, updatedAt: now });
      await apiPutItem(vaultID, itemID, payload);
      await refresh();
    },
    [refresh],
  );

  const removeItem = useCallback(
    async (vaultID: string, itemID: string) => {
      await apiDeleteItem(vaultID, itemID);
      await refresh();
    },
    [refresh],
  );

  const updateItem = useCallback(
    async (vaultID: string, itemID: string, updates: Partial<Pick<VaultItem, 'name' | 'type' | 'data'>>) => {
      const existing = vaults.find((v) => v.id === vaultID)?.items.find((i) => i.id === itemID);
      if (!existing) {
        return;
      }
      const payload = encodeItemPayload({
        name: updates.name ?? existing.name,
        type: updates.type ?? existing.type,
        data: updates.data ?? existing.data,
        createdAt: existing.createdAt,
        updatedAt: new Date().toISOString(),
      });
      await apiUpdateItem(vaultID, itemID, payload);
      await refresh();
    },
    [refresh, vaults],
  );

  const shareVault = useCallback(
    async (vaultID: string, memberID: string, pubKey: string, role: 'owner' | 'writer' | 'reader') => {
      await apiAddMember(vaultID, { memberID, pubKey, role });
      await refresh();
    },
    [refresh],
  );

  const revokeMember = useCallback(
    async (vaultID: string, memberID: string) => {
      await apiRevokeMember(vaultID, memberID);
      await refresh();
    },
    [refresh],
  );

  const account = useMemo<AccountState | null>(() => ({ vaults }), [vaults]);
  const isEnrolled = justRegistered;

  useEffect(() => {
    refresh()
      .then(() => setIsUnlocked(true))
      .catch(() => {
        setIsUnlocked(false);
        setVaults([]);
      });
  }, [refresh]);

  return (
    <VaultContext.Provider
      value={{
        isEnrolled,
        isUnlocked,
        account,
        enroll,
        unlock,
        lock,
        refresh,
        createVault,
        deleteVault,
        addItem,
        removeItem,
        updateItem,
        shareVault,
        revokeMember,
        getDecryptedData: (data: string) => data,
      }}
    >
      {children}
    </VaultContext.Provider>
  );
}

export function useVault() {
  const context = useContext(VaultContext);
  if (!context) throw new Error('useVault must be used within VaultProvider');
  return context;
}
