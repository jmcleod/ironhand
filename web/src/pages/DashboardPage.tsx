import { useEffect, useMemo, useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import {
  Box,
  CreditCard,
  Fingerprint,
  KeyRound,
  Plus,
  Search,
  ShieldCheck,
  StickyNote,
  Vault as VaultIcon,
  Wand2,
  X,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import VaultCard from '@/components/VaultCard';
import VaultDetail from '@/components/VaultDetail';
import ItemCard from '@/components/ItemCard';
import CreateVaultDialog from '@/components/CreateVaultDialog';
import ThemeSwitcher from '@/components/ThemeSwitcher';
import PasswordGeneratorDialog from '@/components/PasswordGeneratorDialog';
import TwoFactorDialog from '@/components/TwoFactorDialog';
import PasskeyDialog from '@/components/PasskeyDialog';
import ShareDialog from '@/components/ShareDialog';
import AuditLogDialog from '@/components/AuditLogDialog';
import ExportVaultDialog from '@/components/ExportVaultDialog';
import ImportVaultDialog from '@/components/ImportVaultDialog';
import IssueCertDialog from '@/components/IssueCertDialog';
import MPCDialog from '@/components/MPCDialog';
import SecurityConsoleLayout, { ConsoleView } from '@/components/security-console/SecurityConsoleLayout';
import SecurityOverview from '@/components/security-console/SecurityOverview';
import { ConsolePanel, ConsolePanelHeader, StatusPill } from '@/components/security-console/ConsolePrimitives';
import { searchItemsLocal, groupResultsByVault } from '@/lib/search';
import { ItemType } from '@/types/vault';

const TYPE_FILTERS: { value: ItemType | 'all'; label: string; icon?: React.ReactNode }[] = [
  { value: 'all', label: 'All' },
  { value: 'login', label: 'Login', icon: <KeyRound className="h-3 w-3" /> },
  { value: 'note', label: 'Note', icon: <StickyNote className="h-3 w-3" /> },
  { value: 'card', label: 'Card', icon: <CreditCard className="h-3 w-3" /> },
  { value: 'custom', label: 'Custom', icon: <Box className="h-3 w-3" /> },
];

export default function DashboardPage() {
  const { account, lock, refreshVault } = useVault();
  const [activeView, setActiveView] = useState<ConsoleView>('overview');
  const [activeVaultId, setActiveVaultId] = useState<string | null>(null);
  const [openVaultId, setOpenVaultId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showTwoFactor, setShowTwoFactor] = useState(false);
  const [showPasskey, setShowPasskey] = useState(false);
  const [showShare, setShowShare] = useState(false);
  const [showAudit, setShowAudit] = useState(false);
  const [showExport, setShowExport] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [showIssueCert, setShowIssueCert] = useState(false);
  const [showMPC, setShowMPC] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ItemType | 'all'>('all');

  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchQuery), 200);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  useEffect(() => {
    if (!account || account.vaults.length === 0) {
      setActiveVaultId(null);
      setOpenVaultId(null);
      return;
    }
    if (!activeVaultId || !account.vaults.some((vault) => vault.id === activeVaultId)) {
      setActiveVaultId(account.vaults[0].id);
    }
  }, [account, activeVaultId]);

  const isSearchActive = debouncedQuery.trim() !== '' || typeFilter !== 'all';

  const searchResults = useMemo(() => {
    if (!account || !isSearchActive) return [];
    return searchItemsLocal(account.vaults, debouncedQuery, typeFilter);
  }, [account, debouncedQuery, typeFilter, isSearchActive]);

  const groupedResults = useMemo(
    () => groupResultsByVault(searchResults),
    [searchResults],
  );

  if (!account) return null;

  const activeVault = account.vaults.find((vault) => vault.id === activeVaultId) ?? account.vaults[0] ?? null;
  const openVault = account.vaults.find((vault) => vault.id === openVaultId) ?? null;
  const totalItems = account.vaults.reduce((sum, vault) => sum + vault.items.length, 0);
  const activeMembers = activeVault?.members.filter((member) => member.status !== 'revoked').length ?? 0;
  const revokedMembers = activeVault?.members.filter((member) => member.status === 'revoked').length ?? 0;

  const renderVaults = () => {
    if (openVault) {
      return <VaultDetail vault={openVault} onBack={() => setOpenVaultId(null)} />;
    }

    if (account.vaults.length === 0) {
      return (
        <ConsolePanel className="flex min-h-[520px] flex-col items-center justify-center p-8 text-center">
          <div className="mb-6 flex h-20 w-20 items-center justify-center rounded-lg bg-muted">
            <VaultIcon className="h-10 w-10 text-muted-foreground" />
          </div>
          <h2 className="mb-2 text-xl font-semibold">No Vaults Yet</h2>
          <p className="mb-6 max-w-sm text-sm text-muted-foreground">Create your first vault to start storing secrets.</p>
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            Create Vault
          </Button>
        </ConsolePanel>
      );
    }

    return (
      <div>
        <div className="mb-5 flex flex-col gap-3 md:flex-row md:items-center md:justify-between">
          <div>
            <p className="console-kicker mb-1">Vaults</p>
            <h1 className="text-2xl font-semibold">Secret Inventory</h1>
          </div>
          <Button onClick={() => setShowCreate(true)}>
            <Plus className="h-4 w-4" />
            New Vault
          </Button>
        </div>

        {totalItems > 0 && (
          <div className="mb-6 space-y-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
              <Input
                placeholder="Search items across all vaults..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="border-border bg-muted pl-9 pr-9"
              />
              {searchQuery && (
                <button
                  onClick={() => { setSearchQuery(''); setDebouncedQuery(''); }}
                  className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                >
                  <X className="h-4 w-4" />
                </button>
              )}
            </div>
            <div className="flex flex-wrap items-center gap-1.5">
              {TYPE_FILTERS.map((filter) => (
                <Button
                  key={filter.value}
                  variant={typeFilter === filter.value ? 'default' : 'ghost'}
                  size="sm"
                  className="h-7 gap-1 px-2.5 text-xs"
                  onClick={() => setTypeFilter(filter.value)}
                >
                  {filter.icon}
                  {filter.label}
                </Button>
              ))}
            </div>
          </div>
        )}

        {isSearchActive ? (
          <div>
            <p className="mb-4 text-sm text-muted-foreground">
              {searchResults.length} item{searchResults.length !== 1 ? 's' : ''} found
            </p>
            {searchResults.length === 0 ? (
              <ConsolePanel className="flex flex-col items-center justify-center p-12 text-center">
                <Search className="mb-4 h-10 w-10 text-muted-foreground" />
                <h2 className="mb-1 text-lg font-semibold">No items match your search</h2>
                <p className="text-sm text-muted-foreground">Try a different query or change the type filter.</p>
              </ConsolePanel>
            ) : (
              <div className="space-y-6">
                {groupedResults.map(([vault, items]) => (
                  <div key={vault.id}>
                    <button
                      onClick={() => {
                        setSearchQuery('');
                        setDebouncedQuery('');
                        setTypeFilter('all');
                        setActiveVaultId(vault.id);
                        setOpenVaultId(vault.id);
                      }}
                      className="mb-2 flex items-center gap-1.5 text-sm font-medium text-muted-foreground transition-colors hover:text-foreground"
                    >
                      <VaultIcon className="h-3.5 w-3.5" />
                      {vault.name}
                      <span className="text-xs">({items.length})</span>
                    </button>
                    <div className="space-y-3">
                      {items.map((item) => (
                        <ItemCard key={item.id} item={item} vaultId={vault.id} />
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        ) : (
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {account.vaults.map((vault) => (
              <VaultCard
                key={vault.id}
                vault={vault}
                onClick={() => {
                  setActiveVaultId(vault.id);
                  setOpenVaultId(vault.id);
                }}
              />
            ))}
          </div>
        )}
      </div>
    );
  };

  const renderPlaceholder = (view: ConsoleView) => (
    <ConsolePanel className="p-6">
      <ConsolePanelHeader
        title={view}
        eyebrow="Console section"
        action={<StatusPill tone="warning">Milestone 3</StatusPill>}
      />
      <p className="mt-4 max-w-2xl text-sm text-muted-foreground">
        This section is now routed through the new security-console shell. The next milestone replaces this placeholder with the operational panels from the mockup and wires available data into each view.
      </p>
      <div className="mt-6 flex flex-wrap gap-2">
        <Button variant="outline" onClick={() => setShowGenerator(true)}>
          <Wand2 className="h-4 w-4" />
          Password Generator
        </Button>
        <Button variant="outline" onClick={() => setShowTwoFactor(true)}>
          <ShieldCheck className="h-4 w-4" />
          Two-Factor
        </Button>
        <Button variant="outline" onClick={() => setShowPasskey(true)}>
          <Fingerprint className="h-4 w-4" />
          Passkeys
        </Button>
        <ThemeSwitcher />
      </div>
    </ConsolePanel>
  );

  const content = activeView === 'overview' ? (
    <SecurityOverview
      vault={activeVault}
      twoFactorEnabled={account.twoFactorEnabled}
      passkeyCount={account.webauthnCredentialCount ?? 0}
      recoveryCodesUnused={account.recoveryCodesUnused}
      onRotate={() => setActiveView('settings')}
      onInvite={() => activeVault && setShowShare(true)}
      onRevoke={() => activeVault && setShowShare(true)}
      onIssueCert={() => activeVault && setShowIssueCert(true)}
      onViewCA={() => setActiveView('ca')}
      onMPC={() => activeVault && setShowMPC(true)}
      onAudit={() => activeVault && setShowAudit(true)}
      onLock={() => { void lock(); }}
    />
  ) : activeView === 'vaults' ? renderVaults() : renderPlaceholder(activeView);

  return (
    <>
      <SecurityConsoleLayout
        activeView={activeView}
        activeVault={activeVault}
        vaults={account.vaults}
        activeMembers={activeMembers}
        revokedMembers={revokedMembers}
        twoFactorEnabled={account.twoFactorEnabled}
        passkeyCount={account.webauthnCredentialCount ?? 0}
        onViewChange={(view) => {
          setActiveView(view);
          setOpenVaultId(null);
        }}
        onVaultChange={(vaultId) => {
          setActiveVaultId(vaultId);
          setOpenVaultId(null);
        }}
        onLock={() => { void lock(); }}
        onInvite={() => activeVault && setShowShare(true)}
        onIssueCert={() => activeVault && setShowIssueCert(true)}
        onMPC={() => activeVault && setShowMPC(true)}
        onAudit={() => activeVault && setShowAudit(true)}
        onImport={() => activeVault && setShowImport(true)}
        onExport={() => activeVault && setShowExport(true)}
      >
        {content}
      </SecurityConsoleLayout>

      <CreateVaultDialog open={showCreate} onOpenChange={setShowCreate} />
      <PasswordGeneratorDialog open={showGenerator} onOpenChange={setShowGenerator} />
      <TwoFactorDialog open={showTwoFactor} onOpenChange={setShowTwoFactor} />
      <PasskeyDialog open={showPasskey} onOpenChange={setShowPasskey} />
      {activeVault && (
        <>
          <ShareDialog open={showShare} onOpenChange={setShowShare} vaultId={activeVault.id} members={activeVault.members} />
          <AuditLogDialog open={showAudit} onOpenChange={setShowAudit} vaultId={activeVault.id} />
          <ExportVaultDialog open={showExport} onOpenChange={setShowExport} vaultId={activeVault.id} vaultName={activeVault.name} />
          <ImportVaultDialog open={showImport} onOpenChange={setShowImport} vaultId={activeVault.id} />
          <IssueCertDialog
            open={showIssueCert}
            onOpenChange={setShowIssueCert}
            vaultId={activeVault.id}
            onSuccess={() => { void refreshVault(activeVault.id); }}
          />
          <MPCDialog
            open={showMPC}
            onOpenChange={setShowMPC}
            vaultId={activeVault.id}
            members={activeVault.members}
            onChanged={() => { void refreshVault(activeVault.id); }}
          />
        </>
      )}
    </>
  );
}
