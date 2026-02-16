import { useEffect, useMemo, useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Plus, Lock, ShieldCheck, Wand2, Vault as VaultIcon, Search, X, KeyRound, StickyNote, CreditCard, Box } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import VaultCard from '@/components/VaultCard';
import VaultDetail from '@/components/VaultDetail';
import ItemCard from '@/components/ItemCard';
import CreateVaultDialog from '@/components/CreateVaultDialog';
import ThemeSwitcher from '@/components/ThemeSwitcher';
import PasswordGeneratorDialog from '@/components/PasswordGeneratorDialog';
import TwoFactorDialog from '@/components/TwoFactorDialog';
import { searchItems, groupResultsByVault } from '@/lib/search';
import { ItemType } from '@/types/vault';
import logo from '@/assets/logo.png';

const TYPE_FILTERS: { value: ItemType | 'all'; label: string; icon?: React.ReactNode }[] = [
  { value: 'all', label: 'All' },
  { value: 'login', label: 'Login', icon: <KeyRound className="h-3 w-3" /> },
  { value: 'note', label: 'Note', icon: <StickyNote className="h-3 w-3" /> },
  { value: 'card', label: 'Card', icon: <CreditCard className="h-3 w-3" /> },
  { value: 'custom', label: 'Custom', icon: <Box className="h-3 w-3" /> },
];

export default function DashboardPage() {
  const { account, lock } = useVault();
  const [selectedVaultId, setSelectedVaultId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);
  const [showTwoFactor, setShowTwoFactor] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ItemType | 'all'>('all');

  // Debounce the search input.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchQuery), 200);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const isSearchActive = debouncedQuery.trim() !== '' || typeFilter !== 'all';

  const searchResults = useMemo(() => {
    if (!account || !isSearchActive) return [];
    return searchItems(account.vaults, debouncedQuery, typeFilter);
  }, [account, debouncedQuery, typeFilter, isSearchActive]);

  const groupedResults = useMemo(
    () => groupResultsByVault(searchResults),
    [searchResults],
  );

  if (!account) return null;

  const selectedVault = account.vaults.find(v => v.id === selectedVaultId);

  if (selectedVault) {
    return <VaultDetail vault={selectedVault} onBack={() => setSelectedVaultId(null)} />;
  }

  const totalItems = account.vaults.reduce((sum, v) => sum + v.items.length, 0);

  return (
    <div className="min-h-screen bg-background">
      {/* Header */}
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-6xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <img src={logo} alt="Ironhand" className="h-9 w-9" />
            <div>
              <h1 className="font-bold text-lg leading-none">Ironhand</h1>
              <p className="text-xs text-muted-foreground mt-0.5">
                {account.vaults.length} vault{account.vaults.length !== 1 ? 's' : ''}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <ThemeSwitcher />
            <Button variant="ghost" size="sm" onClick={() => setShowGenerator(true)} title="Password Generator">
              <Wand2 className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={() => setShowTwoFactor(true)} title="Two-Factor Authentication">
              <ShieldCheck className={`h-4 w-4 ${account.twoFactorEnabled ? 'text-green-500' : ''}`} />
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4 mr-1" />
              New Vault
            </Button>
            <Button variant="ghost" size="sm" onClick={lock}>
              <Lock className="h-4 w-4 mr-1" />
              Lock
            </Button>
          </div>
        </div>
      </header>

      {/* Content */}
      <main className="max-w-6xl mx-auto px-6 py-8">
        {account.vaults.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-24 animate-fade-in">
            <div className="h-20 w-20 rounded-2xl bg-muted flex items-center justify-center mb-6">
              <VaultIcon className="h-10 w-10 text-muted-foreground" />
            </div>
            <h2 className="text-xl font-semibold mb-2">No Vaults Yet</h2>
            <p className="text-muted-foreground text-sm mb-6">Create your first vault to start storing secrets.</p>
            <Button onClick={() => setShowCreate(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Create Vault
            </Button>
          </div>
        ) : (
          <>
            {/* Search bar + type filter */}
            {totalItems > 0 && (
              <div className="mb-6 space-y-3 animate-fade-in">
                <div className="relative">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search items across all vaults..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="pl-9 pr-9 bg-muted border-border"
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
                <div className="flex items-center gap-1.5">
                  {TYPE_FILTERS.map((f) => (
                    <Button
                      key={f.value}
                      variant={typeFilter === f.value ? 'default' : 'ghost'}
                      size="sm"
                      className="h-7 text-xs px-2.5 gap-1"
                      onClick={() => setTypeFilter(f.value)}
                    >
                      {f.icon}
                      {f.label}
                    </Button>
                  ))}
                </div>
              </div>
            )}

            {/* Search results or vault grid */}
            {isSearchActive ? (
              <div className="animate-fade-in">
                <p className="text-sm text-muted-foreground mb-4">
                  {searchResults.length} item{searchResults.length !== 1 ? 's' : ''} found
                </p>
                {searchResults.length === 0 ? (
                  <div className="flex flex-col items-center justify-center py-16">
                    <Search className="h-10 w-10 text-muted-foreground mb-4" />
                    <h2 className="text-lg font-semibold mb-1">No items match your search</h2>
                    <p className="text-sm text-muted-foreground">Try a different query or change the type filter.</p>
                  </div>
                ) : (
                  <div className="space-y-6">
                    {groupedResults.map(([vault, items]) => (
                      <div key={vault.id}>
                        <button
                          onClick={() => { setSearchQuery(''); setDebouncedQuery(''); setTypeFilter('all'); setSelectedVaultId(vault.id); }}
                          className="text-sm font-medium text-muted-foreground hover:text-foreground mb-2 flex items-center gap-1.5 transition-colors"
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
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-fade-in">
                {account.vaults.map(vault => (
                  <VaultCard key={vault.id} vault={vault} onClick={() => setSelectedVaultId(vault.id)} />
                ))}
              </div>
            )}
          </>
        )}
      </main>

      <CreateVaultDialog open={showCreate} onOpenChange={setShowCreate} />
      <PasswordGeneratorDialog open={showGenerator} onOpenChange={setShowGenerator} />
      <TwoFactorDialog open={showTwoFactor} onOpenChange={setShowTwoFactor} />
    </div>
  );
}
