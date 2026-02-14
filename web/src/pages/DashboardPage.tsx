import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Plus, Lock, Vault as VaultIcon } from 'lucide-react';
import { Button } from '@/components/ui/button';
import VaultCard from '@/components/VaultCard';
import VaultDetail from '@/components/VaultDetail';
import CreateVaultDialog from '@/components/CreateVaultDialog';
import ThemeSwitcher from '@/components/ThemeSwitcher';
import logo from '@/assets/logo.png';

export default function DashboardPage() {
  const { account, lock, isUnlocked } = useVault();
  const [selectedVaultId, setSelectedVaultId] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);

  if (!account) return null;

  const selectedVault = account.vaults.find(v => v.id === selectedVaultId);

  if (selectedVault) {
    return <VaultDetail vault={selectedVault} onBack={() => setSelectedVaultId(null)} />;
  }

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
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4 animate-fade-in">
            {account.vaults.map(vault => (
              <VaultCard key={vault.id} vault={vault} onClick={() => setSelectedVaultId(vault.id)} />
            ))}
          </div>
        )}
      </main>

      <CreateVaultDialog open={showCreate} onOpenChange={setShowCreate} />
    </div>
  );
}
