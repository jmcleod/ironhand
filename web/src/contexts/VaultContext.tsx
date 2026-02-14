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
import { FIELD_CREATED, FIELD_NAME, FIELD_TYPE, FIELD_UPDATED, ItemType, Vault, VaultItem } from '@/types/vault';

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
  addItem: (vaultId: string, name: string, type: ItemType, fields: Record<string, string>) => Promise<void>;
  removeItem: (vaultId: string, itemId: string) => Promise<void>;
  updateItem: (vaultId: string, itemId: string, fields: Record<string, string>) => Promise<void>;
  shareVault: (vaultId: string, memberID: string, pubKey: string, role: 'owner' | 'writer' | 'reader') => Promise<void>;
  revokeMember: (vaultId: string, memberID: string) => Promise<void>;
}

const VaultContext = createContext<VaultContextType | null>(null);

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
        const fields = await apiGetItem(summary.vault_id, itemID).catch(() => null);
        if (!fields) {
          continue;
        }
        items.push({ id: itemID, fields });
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
    async (vaultID: string, name: string, type: ItemType, userFields: Record<string, string>) => {
      const now = new Date().toISOString();
      const itemID = generateId();
      const fields: Record<string, string> = {
        ...userFields,
        [FIELD_NAME]: name,
        [FIELD_TYPE]: type,
        [FIELD_CREATED]: now,
        [FIELD_UPDATED]: now,
      };
      await apiPutItem(vaultID, itemID, fields);
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
    async (vaultID: string, itemID: string, fields: Record<string, string>) => {
      const existing = vaults.find((v) => v.id === vaultID)?.items.find((i) => i.id === itemID);
      if (!existing) {
        return;
      }
      const merged: Record<string, string> = {
        ...existing.fields,
        ...fields,
        [FIELD_UPDATED]: new Date().toISOString(),
      };
      await apiUpdateItem(vaultID, itemID, merged);
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
