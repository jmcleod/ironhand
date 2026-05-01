import {
  Bell,
  Building2,
  ChevronDown,
  Download,
  FileClock,
  Fingerprint,
  KeyRound,
  Lock,
  Network,
  Search,
  Settings,
  Shield,
  ShieldCheck,
  Upload,
  UserRoundPlus,
  UsersRound,
  Vault as VaultIcon,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Vault } from '@/types/vault';
import { cn } from '@/lib/utils';
import logo from '@/assets/logo.png';

export type ConsoleView = 'overview' | 'vaults' | 'members' | 'access' | 'ca' | 'mpc' | 'audit' | 'settings';

const TOP_NAV: { id: ConsoleView; label: string }[] = [
  { id: 'overview', label: 'Overview' },
  { id: 'vaults', label: 'Vaults' },
  { id: 'members', label: 'Members' },
  { id: 'access', label: 'Access' },
  { id: 'ca', label: 'CA' },
  { id: 'mpc', label: 'MPC' },
  { id: 'audit', label: 'Audit' },
  { id: 'settings', label: 'Settings' },
];

const SIDE_NAV: { id: ConsoleView | 'secrets' | 'imports'; label: string; icon: React.ReactNode }[] = [
  { id: 'overview', label: 'Overview', icon: <ShieldCheck className="h-4 w-4" /> },
  { id: 'vaults', label: 'Secrets', icon: <Lock className="h-4 w-4" /> },
  { id: 'ca', label: 'Certificates', icon: <FileClock className="h-4 w-4" /> },
  { id: 'mpc', label: 'MPC', icon: <Network className="h-4 w-4" /> },
  { id: 'access', label: 'Access Requests', icon: <UsersRound className="h-4 w-4" /> },
  { id: 'audit', label: 'Audit Log', icon: <FileClock className="h-4 w-4" /> },
  { id: 'imports', label: 'Imports / Exports', icon: <Upload className="h-4 w-4" /> },
  { id: 'settings', label: 'Settings', icon: <Settings className="h-4 w-4" /> },
];

interface SecurityConsoleLayoutProps {
  activeView: ConsoleView;
  activeVault: Vault | null;
  vaults: Vault[];
  activeMembers: number;
  revokedMembers: number;
  twoFactorEnabled: boolean;
  passkeyCount: number;
  onViewChange: (view: ConsoleView) => void;
  onVaultChange: (vaultId: string) => void;
  onLock: () => void;
  onInvite: () => void;
  onIssueCert: () => void;
  onMPC: () => void;
  onAudit: () => void;
  onImport: () => void;
  onExport: () => void;
  children: React.ReactNode;
}

export default function SecurityConsoleLayout({
  activeView,
  activeVault,
  vaults,
  activeMembers,
  revokedMembers,
  twoFactorEnabled,
  passkeyCount,
  onViewChange,
  onVaultChange,
  onLock,
  onInvite,
  onIssueCert,
  onMPC,
  onAudit,
  onImport,
  onExport,
  children,
}: SecurityConsoleLayoutProps) {
  const securityLabel = twoFactorEnabled && passkeyCount > 0 ? 'Everything Secure' : 'Security Attention';

  return (
    <div className="console-shell min-h-screen text-foreground">
      <div className="grid min-h-screen grid-cols-1 lg:grid-cols-[280px_minmax(0,1fr)]">
        <aside className="hidden border-r border-border/80 bg-sidebar/80 lg:flex lg:flex-col">
          <div className="flex h-16 items-center gap-3 border-b border-border/80 px-4">
            <img src={logo} alt="Ironhand" className="h-9 w-9" />
            <div className="min-w-0">
              <div className="text-lg font-bold uppercase tracking-[0.08em]">Ironhand</div>
              <div className="text-[0.65rem] font-semibold uppercase tracking-[0.18em] text-primary">
                Security Console
              </div>
            </div>
          </div>

          <div className="space-y-5 px-4 py-5">
            <div>
              <p className="console-kicker mb-2">Organization</p>
              <button className="flex h-11 w-full items-center justify-between rounded-md border border-transparent px-2 text-left text-sm font-semibold hover:border-border hover:bg-muted/40">
                <span className="flex min-w-0 items-center gap-2">
                  <Building2 className="h-4 w-4 text-muted-foreground" />
                  <span className="truncate">Personal Vaults</span>
                </span>
                <ChevronDown className="h-4 w-4 text-muted-foreground" />
              </button>
            </div>

            <div>
              <p className="console-kicker mb-2">Vault</p>
              <select
                value={activeVault?.id ?? ''}
                onChange={(event) => onVaultChange(event.target.value)}
                className="h-10 w-full rounded-md border border-primary/35 bg-muted/40 px-3 text-sm font-semibold text-foreground outline-none focus:ring-2 focus:ring-primary/40"
                disabled={vaults.length === 0}
              >
                {vaults.length === 0 ? (
                  <option value="">No vaults</option>
                ) : (
                  vaults.map((vault) => (
                    <option key={vault.id} value={vault.id}>
                      {vault.name}
                    </option>
                  ))
                )}
              </select>
            </div>

            <nav className="space-y-1">
              {SIDE_NAV.map((item) => {
                const target = item.id === 'imports' ? 'vaults' : item.id;
                const isActive = activeView === target;
                return (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => {
                      if (item.id === 'imports') {
                        onImport();
                        return;
                      }
                      onViewChange(item.id as ConsoleView);
                    }}
                    className={cn(
                      'flex h-10 w-full items-center gap-3 rounded-md px-3 text-left text-sm transition-colors',
                      isActive
                        ? 'bg-muted text-primary'
                        : 'text-sidebar-foreground hover:bg-muted/60 hover:text-foreground',
                    )}
                  >
                    {item.icon}
                    <span>{item.label}</span>
                  </button>
                );
              })}
            </nav>
          </div>

          <div className="mt-auto border-t border-border/80 p-4">
            <div className="space-y-4 rounded-lg bg-muted/35 p-4">
              <div>
                <p className="console-kicker mb-1">Encryption Epoch</p>
                <div className="text-3xl font-semibold text-primary">{activeVault?.epoch ?? 0}</div>
              </div>
              <div>
                <p className="console-kicker mb-1">Active Members</p>
                <div className="text-2xl text-foreground">{activeMembers}</div>
              </div>
              {revokedMembers > 0 && (
                <div>
                  <p className="console-kicker mb-1">Revoked Members</p>
                  <div className="text-2xl text-red-400">{revokedMembers}</div>
                </div>
              )}
              <div>
                <p className="console-kicker mb-2">Session</p>
                <Button variant="outline" className="w-full justify-center" onClick={onLock}>
                  <Lock className="h-4 w-4" />
                  Lock Session
                </Button>
              </div>
            </div>
          </div>
        </aside>

        <div className="flex min-w-0 flex-col pb-24 lg:pb-28">
          <header className="sticky top-0 z-20 border-b border-border/80 bg-background/82 backdrop-blur-xl">
            <div className="flex h-16 items-center gap-3 px-4 lg:px-6">
              <div className="flex items-center gap-3 lg:hidden">
                <img src={logo} alt="Ironhand" className="h-8 w-8" />
                <span className="text-sm font-bold uppercase tracking-[0.08em]">Ironhand</span>
              </div>
              <nav className="hidden h-full items-center gap-2 lg:flex">
                {TOP_NAV.map((item) => (
                  <button
                    key={item.id}
                    type="button"
                    onClick={() => onViewChange(item.id)}
                    className={cn(
                      'relative flex h-full min-w-24 items-center justify-center px-3 text-sm font-semibold text-muted-foreground transition-colors hover:text-foreground',
                      activeView === item.id && 'text-primary',
                    )}
                  >
                    {item.label}
                    {activeView === item.id && (
                      <span className="absolute bottom-0 left-3 right-3 h-0.5 rounded-full bg-primary" />
                    )}
                  </button>
                ))}
              </nav>
              <div className="ml-auto flex items-center gap-2">
                <div className="hidden h-10 items-center gap-2 rounded-md border border-border bg-muted/35 px-3 text-sm font-medium md:flex">
                  <ShieldCheck className={cn('h-4 w-4', securityLabel === 'Everything Secure' ? 'text-primary' : 'text-amber-400')} />
                  {securityLabel}
                </div>
                <Button variant="outline" size="icon" onClick={onLock} title="Lock session">
                  <Lock className="h-4 w-4" />
                </Button>
                <Button variant="ghost" size="icon" title="Notifications">
                  <Bell className="h-4 w-4" />
                </Button>
                <div className="hidden h-10 items-center gap-2 rounded-md border border-border bg-muted/35 px-2 md:flex">
                  <div className="flex h-7 w-7 items-center justify-center rounded-full bg-muted text-xs font-semibold">
                    IH
                  </div>
                  <ChevronDown className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            </div>
          </header>

          <main className="min-w-0 flex-1 p-4 lg:p-6">{children}</main>
        </div>
      </div>

      <div className="fixed inset-x-3 bottom-3 z-30 rounded-lg border border-border bg-background/92 p-2 shadow-2xl backdrop-blur-xl lg:inset-x-6">
        <div className="flex flex-col gap-2 lg:flex-row lg:items-center">
          <button
            type="button"
            className="flex h-12 min-w-0 flex-1 items-center gap-3 rounded-md border border-border bg-muted/35 px-4 text-left text-muted-foreground hover:border-primary/40 hover:text-foreground"
          >
            <Search className="h-5 w-5" />
            <span className="truncate text-sm">Type a command or search...</span>
            <span className="ml-auto hidden rounded border border-border px-2 py-1 text-xs font-semibold text-muted-foreground sm:inline-flex">
              ⌘ K
            </span>
          </button>
          <div className="flex min-w-0 gap-1 overflow-x-auto">
            <Button variant="ghost" className="shrink-0" onClick={() => onViewChange('vaults')}>
              <VaultIcon className="h-4 w-4" />
              Vaults
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={onInvite} disabled={!activeVault}>
              <UserRoundPlus className="h-4 w-4" />
              Invite
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={onIssueCert} disabled={!activeVault}>
              <Shield className="h-4 w-4" />
              Issue Cert
            </Button>
            <Button variant="ghost" className="shrink-0 text-primary" onClick={onMPC} disabled={!activeVault}>
              <KeyRound className="h-4 w-4" />
              Sign MPC
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={onAudit} disabled={!activeVault}>
              <ShieldCheck className="h-4 w-4" />
              Verify Audit
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={onExport} disabled={!activeVault}>
              <Download className="h-4 w-4" />
              Export
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={onImport} disabled={!activeVault}>
              <Upload className="h-4 w-4" />
              Import
            </Button>
            <Button variant="ghost" className="shrink-0" onClick={() => onViewChange('settings')}>
              <Fingerprint className="h-4 w-4" />
              Security
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}

