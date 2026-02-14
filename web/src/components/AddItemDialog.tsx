import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { ItemType } from '@/types/vault';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { useToast } from '@/hooks/use-toast';

interface AddItemDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
}

export default function AddItemDialog({ open, onOpenChange, vaultId }: AddItemDialogProps) {
  const { addItem } = useVault();
  const { toast } = useToast();
  const [name, setName] = useState('');
  const [type, setType] = useState<ItemType>('text');
  const [data, setData] = useState('');
  const [saving, setSaving] = useState(false);

  const handleAdd = async () => {
    if (!name.trim() || !data.trim()) return;
    setSaving(true);
    try {
      await addItem(vaultId, name.trim(), type, data);
      setName('');
      setType('text');
      setData('');
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to add item.';
      toast({ title: 'Add item failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const getPlaceholder = () => {
    switch (type) {
      case 'text': return 'Enter secret text, password, API key, etc.';
      case 'image': return 'Enter image URL';
      case 'email': return 'From: sender@example.com\nTo: recipient@example.com\nSubject: Secret\nBody: Content here';
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle>Add Secret Item</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Item name" className="bg-muted border-border" />
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Type</label>
            <Select value={type} onValueChange={(v: ItemType) => setType(v)}>
              <SelectTrigger className="bg-muted border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-popover border-border">
                <SelectItem value="text">Text / Secret</SelectItem>
                <SelectItem value="image">Image URL</SelectItem>
                <SelectItem value="email">Email</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div>
            <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Data</label>
            <Textarea
              value={data}
              onChange={e => setData(e.target.value)}
              placeholder={getPlaceholder()}
              rows={type === 'email' ? 6 : 3}
              className="bg-muted border-border font-mono text-sm"
            />
          </div>
          <Button className="w-full" onClick={handleAdd} disabled={saving || !name.trim() || !data.trim()}>
            {saving ? 'Adding...' : 'Add Item'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
