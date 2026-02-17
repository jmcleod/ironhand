import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { exportVault } from '@/lib/api';
import { Eye, EyeOff } from 'lucide-react';

interface ExportVaultDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  vaultName: string;
}

export default function ExportVaultDialog({ open, onOpenChange, vaultId, vaultName }: ExportVaultDialogProps) {
  const { toast } = useToast();
  const [passphrase, setPassphrase] = useState('');
  const [confirm, setConfirm] = useState('');
  const [showPassword, setShowPassword] = useState(false);
  const [exporting, setExporting] = useState(false);

  const canExport = passphrase.length > 0 && passphrase === confirm;

  const handleExport = async () => {
    if (!canExport) return;
    setExporting(true);
    try {
      const blob = await exportVault(vaultId, passphrase);
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      const safeName = vaultName.replace(/[^a-zA-Z0-9_-]/g, '_') || 'vault';
      a.download = `${safeName}-backup.ironhand-backup`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);

      toast({ title: 'Export complete', description: 'Backup file downloaded.' });
      setPassphrase('');
      setConfirm('');
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Export failed.';
      toast({ title: 'Export failed', description: msg, variant: 'destructive' });
    } finally {
      setExporting(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) { setPassphrase(''); setConfirm(''); } }}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle>Export Vault Backup</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          This will create an encrypted backup of all items in this vault. Choose a strong passphrase to protect the backup file.
        </p>
        <div className="space-y-3 mt-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
              Backup Passphrase
            </label>
            <div className="relative">
              <Input
                type={showPassword ? 'text' : 'password'}
                value={passphrase}
                onChange={(e) => setPassphrase(e.target.value)}
                placeholder="Enter a strong passphrase"
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
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
              Confirm Passphrase
            </label>
            <Input
              type={showPassword ? 'text' : 'password'}
              value={confirm}
              onChange={(e) => setConfirm(e.target.value)}
              placeholder="Confirm passphrase"
              className="bg-muted border-border"
            />
            {confirm && passphrase !== confirm && (
              <p className="text-xs text-destructive mt-1">Passphrases do not match.</p>
            )}
          </div>
          <Button className="w-full" onClick={handleExport} disabled={exporting || !canExport}>
            {exporting ? 'Exporting...' : 'Export Backup'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
