import { useEffect } from 'react';
import {
  Download,
  FileKey2,
  KeyRound,
  Lock,
  Network,
  Plus,
  Search,
  Settings,
  ShieldCheck,
  Upload,
  UserRoundPlus,
  Vault as VaultIcon,
} from 'lucide-react';
import {
  CommandDialog,
  CommandEmpty,
  CommandGroup,
  CommandInput,
  CommandItem,
  CommandList,
  CommandSeparator,
  CommandShortcut,
} from '@/components/ui/command';
import { ConsoleView } from '@/components/security-console/SecurityConsoleLayout';
import { itemName, Vault } from '@/types/vault';

const NAV_COMMANDS = [
  { label: 'Overview', view: 'overview' as const, icon: ShieldCheck },
  { label: 'Vaults', view: 'vaults' as const, icon: VaultIcon },
  { label: 'Members', view: 'members' as const, icon: UserRoundPlus },
  { label: 'Access', view: 'access' as const, icon: UserRoundPlus },
  { label: 'Certificate Authority', view: 'ca' as const, icon: FileKey2 },
  { label: 'MPC', view: 'mpc' as const, icon: Network },
  { label: 'Audit', view: 'audit' as const, icon: ShieldCheck },
  { label: 'Settings', view: 'settings' as const, icon: Settings },
];

interface ConsoleCommandPaletteProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaults: Vault[];
  activeVault: Vault | null;
  onViewChange: (view: ConsoleView) => void;
  onVaultChange: (vaultId: string) => void;
  onOpenVault: (vaultId: string) => void;
  onCreateVault: () => void;
  onAddItem: () => void;
  onGenerator: () => void;
  onTwoFactor: () => void;
  onInvite: () => void;
  onIssueCert: () => void;
  onMPC: () => void;
  onAudit: () => void;
  onImport: () => void;
  onExport: () => void;
  onLock: () => void;
}

export default function ConsoleCommandPalette({
  open,
  onOpenChange,
  vaults,
  activeVault,
  onViewChange,
  onVaultChange,
  onOpenVault,
  onCreateVault,
  onAddItem,
  onGenerator,
  onTwoFactor,
  onInvite,
  onIssueCert,
  onMPC,
  onAudit,
  onImport,
  onExport,
  onLock,
}: ConsoleCommandPaletteProps) {
  useEffect(() => {
    const onKeyDown = (event: KeyboardEvent) => {
      if ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === 'k') {
        event.preventDefault();
        onOpenChange(!open);
      }
    };
    document.addEventListener('keydown', onKeyDown);
    return () => document.removeEventListener('keydown', onKeyDown);
  }, [onOpenChange, open]);

  const run = (action: () => void) => {
    action();
    onOpenChange(false);
  };

  return (
    <CommandDialog open={open} onOpenChange={onOpenChange}>
      <CommandInput placeholder="Search vaults, secrets, and commands..." />
      <CommandList className="max-h-[520px]">
        <CommandEmpty>No command or secret found.</CommandEmpty>

        <CommandGroup heading="Navigation">
          {NAV_COMMANDS.map(({ label, view, icon: Icon }) => (
            <CommandItem key={view} onSelect={() => run(() => onViewChange(view))}>
              <Icon className="mr-2 h-4 w-4" />
              {label}
            </CommandItem>
          ))}
        </CommandGroup>

        <CommandSeparator />

        <CommandGroup heading="Actions">
          <CommandItem onSelect={() => run(onCreateVault)}>
            <Plus className="mr-2 h-4 w-4" />
            New Vault
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onAddItem)}>
            <KeyRound className="mr-2 h-4 w-4" />
            Add Secret
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onInvite)}>
            <UserRoundPlus className="mr-2 h-4 w-4" />
            Invite Member
          </CommandItem>
          <CommandItem onSelect={() => run(onGenerator)}>
            <KeyRound className="mr-2 h-4 w-4" />
            Generate Password
          </CommandItem>
          <CommandItem onSelect={() => run(onTwoFactor)}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            Manage Two-Factor
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onIssueCert)}>
            <FileKey2 className="mr-2 h-4 w-4" />
            Issue Certificate
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onMPC)}>
            <KeyRound className="mr-2 h-4 w-4" />
            Sign MPC Request
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onAudit)}>
            <ShieldCheck className="mr-2 h-4 w-4" />
            View Audit Log
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onExport)}>
            <Download className="mr-2 h-4 w-4" />
            Export Vault
          </CommandItem>
          <CommandItem disabled={!activeVault} onSelect={() => run(onImport)}>
            <Upload className="mr-2 h-4 w-4" />
            Import Vault
          </CommandItem>
          <CommandItem onSelect={() => run(onLock)}>
            <Lock className="mr-2 h-4 w-4" />
            Lock Session
            <CommandShortcut>Esc</CommandShortcut>
          </CommandItem>
        </CommandGroup>

        {vaults.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Vaults">
              {vaults.map((vault) => (
                <CommandItem
                  key={vault.id}
                  onSelect={() => run(() => {
                    onVaultChange(vault.id);
                    onOpenVault(vault.id);
                  })}
                >
                  <VaultIcon className="mr-2 h-4 w-4" />
                  {vault.name}
                  <span className="ml-2 text-xs text-muted-foreground">{vault.items.length} items</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}

        {vaults.some((vault) => vault.items.length > 0) && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Secrets">
              {vaults.flatMap((vault) => vault.items.map((item) => ({ vault, item }))).slice(0, 18).map(({ vault, item }) => (
                <CommandItem
                  key={`${vault.id}-${item.id}`}
                  value={`${itemName(item)} ${vault.name}`}
                  onSelect={() => run(() => {
                    onVaultChange(vault.id);
                    onOpenVault(vault.id);
                  })}
                >
                  <Search className="mr-2 h-4 w-4" />
                  {itemName(item)}
                  <span className="ml-2 text-xs text-muted-foreground">{vault.name}</span>
                </CommandItem>
              ))}
            </CommandGroup>
          </>
        )}
      </CommandList>
    </CommandDialog>
  );
}
