import { Vault } from '@/types/vault';
import { FolderLock, Share2, Shield } from 'lucide-react';

interface VaultCardProps {
  vault: Vault;
  onClick: () => void;
}

export default function VaultCard({ vault, onClick }: VaultCardProps) {
  return (
    <button
      onClick={onClick}
      className="w-full text-left rounded-2xl border border-border bg-card p-6 vault-card-hover group"
    >
      <div className="flex items-start justify-between mb-4">
        <div className="h-11 w-11 rounded-xl bg-accent flex items-center justify-center group-hover:glow-primary-sm transition-all">
          <FolderLock className="h-5 w-5 text-primary" />
        </div>
        <div className="flex items-center gap-1.5">
          {vault.isCA && (
            <div className="flex items-center gap-1 text-xs text-primary bg-primary/10 px-2 py-1 rounded-full" title="Certificate Authority">
              <Shield className="h-3 w-3" />
              CA
            </div>
          )}
          {vault.members.length > 1 && (
            <div className="flex items-center gap-1 text-xs text-muted-foreground bg-muted px-2 py-1 rounded-full">
              <Share2 className="h-3 w-3" />
              {vault.members.length}
            </div>
          )}
        </div>
      </div>
      <h3 className="font-semibold text-foreground mb-1 truncate">{vault.name}</h3>
      <p className="text-sm text-muted-foreground line-clamp-2 mb-3">{vault.description || 'No description'}</p>
      <div className="flex items-center justify-between text-xs text-muted-foreground">
        <span>{vault.items.length} item{vault.items.length !== 1 ? 's' : ''}</span>
        <span>{new Date(vault.updatedAt).toLocaleDateString()}</span>
      </div>
    </button>
  );
}
