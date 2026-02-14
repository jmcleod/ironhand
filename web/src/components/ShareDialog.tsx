import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Users } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';

interface ShareDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  sharedWith: string[];
}

export default function ShareDialog({ open, onOpenChange, vaultId, sharedWith }: ShareDialogProps) {
  const { shareVault, revokeMember } = useVault();
  const { toast } = useToast();
  const [memberID, setMemberID] = useState('');
  const [pubKey, setPubKey] = useState('');
  const [role, setRole] = useState<'owner' | 'writer' | 'reader'>('reader');
  const [saving, setSaving] = useState(false);

  const handleShare = async () => {
    if (!memberID.trim() || !pubKey.trim()) return;
    setSaving(true);
    try {
      await shareVault(vaultId, memberID.trim(), pubKey.trim(), role);
      setMemberID('');
      setPubKey('');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to share vault.';
      toast({ title: 'Share failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const handleRevoke = async (id: string) => {
    try {
      await revokeMember(vaultId, id);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to revoke member.';
      toast({ title: 'Revoke failed', description: msg, variant: 'destructive' });
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Users className="h-5 w-5 text-primary" />
            Share Vault
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div className="flex gap-2">
            <Input
              value={memberID}
              onChange={e => setMemberID(e.target.value)}
              placeholder="Member ID"
              className="bg-muted border-border flex-1"
            />
            <Button onClick={handleShare} disabled={saving || !memberID.trim() || !pubKey.trim()}>
              Share
            </Button>
          </div>
          <Input
            value={pubKey}
            onChange={e => setPubKey(e.target.value)}
            placeholder="Member public key (base64, 32 bytes)"
            className="bg-muted border-border font-mono text-xs"
          />
          <Select value={role} onValueChange={(value: 'owner' | 'writer' | 'reader') => setRole(value)}>
            <SelectTrigger className="bg-muted border-border">
              <SelectValue />
            </SelectTrigger>
            <SelectContent className="bg-popover border-border">
              <SelectItem value="reader">reader</SelectItem>
              <SelectItem value="writer">writer</SelectItem>
              <SelectItem value="owner">owner</SelectItem>
            </SelectContent>
          </Select>

          {sharedWith.length > 0 && (
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
                Shared With
              </label>
              <div className="space-y-2">
                {sharedWith.map(uid => (
                  <div key={uid} className="flex items-center justify-between p-3 rounded-lg bg-muted border border-border">
                    <span className="font-mono text-sm text-foreground">{uid}</span>
                    <Button variant="ghost" size="sm" onClick={() => handleRevoke(uid)}>
                      Revoke
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {sharedWith.length === 0 && (
            <p className="text-sm text-muted-foreground text-center py-4">
              Not shared with anyone yet.
            </p>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
