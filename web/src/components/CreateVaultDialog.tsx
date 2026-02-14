import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';

interface CreateVaultDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function CreateVaultDialog({ open, onOpenChange }: CreateVaultDialogProps) {
  const { createVault } = useVault();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [description, setDescription] = useState('');
  const [saving, setSaving] = useState(false);

  const handleCreate = async () => {
    if (!name.trim()) return;
    setSaving(true);
    try {
      await createVault(name.trim(), description.trim());
      setName('');
      setDescription('');
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create vault.';
      toast({ title: 'Create failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle>Create New Vault</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="My Secrets" className="bg-muted border-border" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Description</label>
            <Input value={description} onChange={e => setDescription(e.target.value)} placeholder="Optional description" className="bg-muted border-border" />
          </div>
          <Button className="w-full" onClick={handleCreate} disabled={saving || !name.trim()}>
            {saving ? 'Creating...' : 'Create Vault'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
