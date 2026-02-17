import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { useVault } from '@/contexts/VaultContext';
import { importVault } from '@/lib/api';
import { Upload, Eye, EyeOff, FileArchive, X } from 'lucide-react';
import { formatFileSize } from '@/types/vault';

interface ImportVaultDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
}

export default function ImportVaultDialog({ open, onOpenChange, vaultId }: ImportVaultDialogProps) {
  const { toast } = useToast();
  const { refresh } = useVault();
  const [file, setFile] = useState<File | null>(null);
  const [passphrase, setPassphrase] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [importing, setImporting] = useState(false);

  const canImport = file !== null && passphrase.length > 0;

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    const selected = e.target.files?.[0] ?? null;
    setFile(selected);
    e.target.value = '';
  };

  const handleImport = async () => {
    if (!canImport || !file) return;
    setImporting(true);
    try {
      const result = await importVault(vaultId, file, passphrase);
      toast({
        title: 'Import complete',
        description: `${result.imported_count} item${result.imported_count === 1 ? '' : 's'} imported.`,
      });
      await refresh();
      setFile(null);
      setPassphrase('');
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Import failed.';
      toast({ title: 'Import failed', description: msg, variant: 'destructive' });
    } finally {
      setImporting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) { setFile(null); setPassphrase(''); } }}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle>Import Vault Backup</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Select an encrypted backup file (.ironhand-backup) and enter the passphrase used to create it. Items will be imported as new entries.
        </p>
        <div className="space-y-3 mt-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
              Backup File
            </label>
            {file ? (
              <div className="flex items-center gap-2 p-2 rounded bg-muted text-sm">
                <FileArchive className="h-4 w-4 text-muted-foreground shrink-0" />
                <span className="flex-1 truncate">{file.name}</span>
                <span className="text-xs text-muted-foreground">{formatFileSize(file.size)}</span>
                <Button variant="ghost" size="icon" onClick={() => setFile(null)} className="h-7 w-7 shrink-0">
                  <X className="h-3.5 w-3.5" />
                </Button>
              </div>
            ) : (
              <label className="flex items-center justify-center gap-2 p-3 border border-dashed border-border rounded-lg cursor-pointer hover:bg-accent/50 transition-colors text-sm text-muted-foreground">
                <Upload className="h-4 w-4" />
                Choose .ironhand-backup file
                <input type="file" accept=".ironhand-backup" className="hidden" onChange={handleFileSelect} />
              </label>
            )}
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
              Backup Passphrase
            </label>
            <div className="relative">
              <Input
                type={showPassword ? 'text' : 'password'}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter the backup passphrase"
                className="bg-muted border-border pr-10"
              />
              <Button
                type="button"
                variant="ghost"
                size="icon"
                className="absolute right-0 top-0 h-full w-10"
                onClick={() => setShowPassword(!showPassword)}
              >
                {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
              </Button>
            </div>
          </div>
          <Button className="w-full" onClick={handleImport} disabled={importing || !canImport}>
            {importing ? 'Importing...' : 'Import Backup'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
