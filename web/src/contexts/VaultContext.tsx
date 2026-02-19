import React, { createContext, useCallback, useContext, useEffect, useMemo, useState } from 'react';
import { startRegistration, startAuthentication } from '@simplewebauthn/browser';
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
  twoFactorStatus as apiTwoFactorStatus,
  putItem as apiPutItem,
  register as apiRegister,
  revokeMember as apiRevokeMember,
  setupTwoFactor as apiSetupTwoFactor,
  enableTwoFactor as apiEnableTwoFactor,
  updateItem as apiUpdateItem,
  getCAInfo as apiGetCAInfo,
  webauthnStatus as apiWebAuthnStatus,
  beginWebAuthnRegistration as apiBeginWebAuthnRegistration,
  finishWebAuthnRegistration as apiFinishWebAuthnRegistration,
  beginWebAuthnLogin as apiBeginWebAuthnLogin,
  finishWebAuthnLogin as apiFinishWebAuthnLogin,
} from '@/lib/api';
import { generateId } from '@/lib/crypto';
import { FIELD_CREATED, FIELD_NAME, FIELD_TYPE, FIELD_UPDATED, ItemType, Vault, VaultItem } from '@/types/vault';

interface AccountState {
  vaults: Vault[];
  twoFactorEnabled: boolean;
  webauthnEnabled: boolean;
  webauthnCredentialCount: number;
}

interface VaultContextType {
  isEnrolled: boolean;
  isUnlocked: boolean;
  account: AccountState | null;
  enroll: (passphrase: string) => Promise<{ secretKey: string }>;
  completeEnrollment: () => void;
  unlock: (secretKey: string, passphrase: string, totpCode?: string) => Promise<boolean>;
  unlockWithPasskey: (secretKey: string, passphrase: string) => Promise<boolean>;
  registerPasskey: () => Promise<void>;
  setupTwoFactor: () => Promise<{ secret: string; otpauthURL: string; expiresAt: string }>;
  enableTwoFactor: (code: string) => Promise<boolean>;
  lock: () => Promise<void>;
  refresh: () => Promise<void>;
  createVault: (name: string, description: string) => Promise<void>;
  deleteVault: (vaultId: string) => Promise<void>;
  addItem: (vaultId: string, name: string, type: ItemType, fields: Record<string, string>) => Promise<void>;
  removeItem: (vaultId: string, itemId: string) => Promise<void>;
  updateItem: (vaultId: string, itemId: string, fields: Record<string, string>, removeKeys?: string[]) => Promise<void>;
  shareVault: (vaultId: string, memberID: string, pubKey: string, role: 'owner' | 'writer' | 'reader') => Promise<void>;
  revokeMember: (vaultId: string, memberID: string) => Promise<void>;
}

const VaultContext = createContext<VaultContextType | null>(null);

export function VaultProvider({ children }: { children: React.ReactNode }) {
  const [isUnlocked, setIsUnlocked] = useState(false);
  const [vaults, setVaults] = useState<Vault[]>([]);
  const [twoFactorEnabled, setTwoFactorEnabled] = useState(false);
  const [webauthnEnabled, setWebauthnEnabled] = useState(false);
  const [webauthnCredentialCount, setWebauthnCredentialCount] = useState(0);
  const [justRegistered, setJustRegistered] = useState(false);

  const refresh = useCallback(async () => {
    const summaries = await apiListVaults();
    const nextVaults: Vault[] = [];
    for (const summary of summaries) {
      const [listed, caInfo] = await Promise.all([
        apiListItems(summary.vault_id).catch(() => []),
        apiGetCAInfo(summary.vault_id).catch(() => null),
      ]);
      const items: VaultItem[] = [];
      for (const item of listed) {
        items.push({
          id: item.item_id,
          fields: {
            [FIELD_NAME]: item.name || item.item_id,
            [FIELD_TYPE]: (item.type as ItemType) || 'custom',
          },
        });
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
        isCA: caInfo?.is_ca ?? false,
      });
    }
    const [tfStatus, waStatus] = await Promise.all([
      apiTwoFactorStatus().catch(() => ({ enabled: false })),
      apiWebAuthnStatus().catch(() => ({ enabled: false, credential_count: 0 })),
    ]);
    setVaults(nextVaults);
    setTwoFactorEnabled(tfStatus.enabled);
    setWebauthnEnabled(waStatus.enabled);
    setWebauthnCredentialCount(waStatus.credential_count);
  }, []);

  const enroll = useCallback(async (passphrase: string) => {
    const result = await apiRegister(passphrase);
    setIsUnlocked(true);
    setJustRegistered(true);
    setVaults([]);
    // Fetch WebAuthn status so the enrollment screen knows passkeys are available.
    const waStatus = await apiWebAuthnStatus().catch(() => ({ enabled: false, credential_count: 0 }));
    setWebauthnEnabled(waStatus.enabled);
    setWebauthnCredentialCount(waStatus.credential_count);
    return { secretKey: result.secret_key };
  }, []);

  const completeEnrollment = useCallback(() => {
    setJustRegistered(false);
    // Trigger a full refresh so the dashboard has current data.
    refresh().catch(() => {});
  }, [refresh]);

  const unlock = useCallback(
    async (secretKey: string, passphrase: string, totpCode?: string) => {
      try {
        await apiLogin(passphrase, secretKey, totpCode);
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

  const unlockWithPasskey = useCallback(
    async (secretKey: string, passphrase: string) => {
      try {
        // eslint-disable-next-line @typescript-eslint/no-explicit-any
        const options = (await apiBeginWebAuthnLogin(secretKey, passphrase)) as any;
        const assertion = await startAuthentication({ optionsJSON: options.publicKey ?? options });
        await apiFinishWebAuthnLogin(assertion);
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

  const registerPasskey = useCallback(async () => {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    const options = (await apiBeginWebAuthnRegistration()) as any;
    const attestation = await startRegistration({ optionsJSON: options.publicKey ?? options });
    await apiFinishWebAuthnRegistration(attestation);
    // Refresh to update credential count.
    const waStatus = await apiWebAuthnStatus().catch(() => ({ enabled: false, credential_count: 0 }));
    setWebauthnEnabled(waStatus.enabled);
    setWebauthnCredentialCount(waStatus.credential_count);
  }, []);

  const setupTwoFactor = useCallback(async () => {
    const out = await apiSetupTwoFactor();
    return {
      secret: out.secret,
      otpauthURL: out.otpauth_url,
      expiresAt: out.expires_at,
    };
  }, []);

  const enableTwoFactor = useCallback(async (code: string) => {
    const out = await apiEnableTwoFactor(code);
    setTwoFactorEnabled(out.enabled);
    return out.enabled;
  }, []);

  const lock = useCallback(async () => {
    await apiLogout().catch(() => undefined);
    setIsUnlocked(false);
    setVaults([]);
    setTwoFactorEnabled(false);
    setWebauthnEnabled(false);
    setWebauthnCredentialCount(0);
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
    async (vaultID: string, itemID: string, fields: Record<string, string>, removeKeys?: string[]) => {
      const existing = await apiGetItem(vaultID, itemID).catch(() => ({}));
      const merged: Record<string, string> = {
        ...existing,
        ...fields,
        [FIELD_UPDATED]: new Date().toISOString(),
      };
      if (removeKeys) {
        for (const key of removeKeys) {
          delete merged[key];
        }
      }
      // Never write back server-redacted sentinel values — they would
      // destroy the real data stored on the backend.
      for (const key of Object.keys(merged)) {
        if (merged[key] === '[REDACTED]') {
          delete merged[key];
        }
      }
      await apiUpdateItem(vaultID, itemID, merged);
      await refresh();
    },
    [refresh],
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

  const account = useMemo<AccountState | null>(
    () => ({ vaults, twoFactorEnabled, webauthnEnabled, webauthnCredentialCount }),
    [twoFactorEnabled, vaults, webauthnEnabled, webauthnCredentialCount],
  );
  const isEnrolled = justRegistered;

  useEffect(() => {
    refresh()
      .then(() => setIsUnlocked(true))
      .catch(() => {
        setIsUnlocked(false);
        setVaults([]);
        setTwoFactorEnabled(false);
        setWebauthnEnabled(false);
        setWebauthnCredentialCount(0);
      });
  }, [refresh]);

  return (
    <VaultContext.Provider
      value={{
        isEnrolled,
        isUnlocked,
        account,
        enroll,
        completeEnrollment,
        unlock,
        unlockWithPasskey,
        registerPasskey,
        setupTwoFactor,
        enableTwoFactor,
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
