import { useState } from 'react';
import { VaultItem } from '@/types/vault';
import { useVault } from '@/contexts/VaultContext';
import { Eye, EyeOff, Trash2, Copy, Check, FileText, Image, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

interface ItemCardProps {
  item: VaultItem;
  vaultId: string;
}

export default function ItemCard({ item, vaultId }: ItemCardProps) {
  const { getDecryptedData, removeItem } = useVault();
  const { toast } = useToast();
  const [revealed, setRevealed] = useState(false);
  const [copied, setCopied] = useState(false);

  const decrypted = revealed ? getDecryptedData(item.data) : null;

  const typeIcon = () => {
    switch (item.type) {
      case 'text': return <FileText className="h-4 w-4 text-primary" />;
      case 'image': return <Image className="h-4 w-4 text-primary" />;
      case 'email': return <Mail className="h-4 w-4 text-primary" />;
    }
  };

  const typeLabel = () => {
    switch (item.type) {
      case 'text': return 'Text';
      case 'image': return 'Image';
      case 'email': return 'Email';
    }
  };

  const handleCopy = () => {
    if (decrypted) {
      navigator.clipboard.writeText(decrypted);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    }
  };

  const handleDelete = async () => {
    if (confirm('Delete this item?')) {
      try {
        await removeItem(vaultId, item.id);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to delete item.';
        toast({ title: 'Delete failed', description: msg, variant: 'destructive' });
      }
    }
  };

  const renderContent = () => {
    if (!revealed || !decrypted) {
      return (
        <div className="font-mono text-sm text-muted-foreground tracking-wider">
          ••••••••••••••••
        </div>
      );
    }

    switch (item.type) {
      case 'image':
        return (
          <div className="mt-2">
            <img src={decrypted} alt={item.name} className="max-w-full max-h-48 rounded-lg border border-border" />
          </div>
        );
      case 'email':
        return (
          <div className="mt-2 space-y-1 text-sm">
            {decrypted.split('\n').map((line, i) => {
              const [key, ...rest] = line.split(':');
              const value = rest.join(':').trim();
              return (
                <div key={i} className="flex gap-2">
                  <span className="text-muted-foreground font-medium min-w-[80px]">{key}:</span>
                  <span className="text-foreground">{value}</span>
                </div>
              );
            })}
          </div>
        );
      default:
        return (
          <pre className="mt-2 font-mono text-sm text-foreground whitespace-pre-wrap bg-muted p-3 rounded-lg border border-border">
            {decrypted}
          </pre>
        );
    }
  };

  return (
    <div className="rounded-xl border border-border bg-card p-5 vault-card-hover">
      <div className="flex items-center justify-between mb-3">
        <div className="flex items-center gap-3">
          <div className="h-9 w-9 rounded-lg bg-accent flex items-center justify-center">
            {typeIcon()}
          </div>
          <div>
            <h3 className="font-medium text-foreground">{item.name}</h3>
            <span className="text-xs text-muted-foreground">{typeLabel()} • {new Date(item.updatedAt).toLocaleDateString()}</span>
          </div>
        </div>
        <div className="flex items-center gap-1">
          <Button variant="ghost" size="icon" onClick={() => setRevealed(!revealed)} className="h-8 w-8">
            {revealed ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
          </Button>
          {revealed && (
            <Button variant="ghost" size="icon" onClick={handleCopy} className="h-8 w-8">
              {copied ? <Check className="h-4 w-4 text-success" /> : <Copy className="h-4 w-4" />}
            </Button>
          )}
          <Button variant="ghost" size="icon" onClick={handleDelete} className="h-8 w-8 text-destructive hover:text-destructive">
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>
      {renderContent()}
    </div>
  );
}
