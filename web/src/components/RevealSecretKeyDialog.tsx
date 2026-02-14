import { useState } from 'react';
import { revealSecretKey } from '@/lib/api';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { Copy, Check, KeyRound, ShieldAlert } from 'lucide-react';

interface RevealSecretKeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function RevealSecretKeyDialog({ open, onOpenChange }: RevealSecretKeyDialogProps) {
  const { toast } = useToast();
  const [passphrase, setPassphrase] = useState('');
  const [secretKey, setSecretKey] = useState('');
  const [loading, setLoading] = useState(false);
  const [copied, setCopied] = useState(false);

  const reset = () => {
    setPassphrase('');
    setSecretKey('');
    setLoading(false);
    setCopied(false);
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const handleReveal = async () => {
    if (!passphrase) return;
    setLoading(true);
    try {
      const key = await revealSecretKey(passphrase);
      setSecretKey(key);
    } catch (err) {
      const msg = err && typeof err === 'object' && 'message' in err ? (err as { message: string }).message : 'Incorrect passphrase.';
      toast({ title: 'Verification failed', description: msg, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  const handleCopy = () => {
    navigator.clipboard.writeText(secretKey);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <KeyRound className="h-5 w-5 text-primary" />
            View Secret Key
          </DialogTitle>
        </DialogHeader>

        {!secretKey ? (
          <div className="space-y-4 mt-2">
            <p className="text-sm text-muted-foreground">
              Enter your passphrase to reveal your secret key.
            </p>
            <div>
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
                Passphrase
              </label>
              <Input
                type="password"
                value={passphrase}
                onChange={e => setPassphrase(e.target.value)}
                placeholder="Enter your passphrase"
                className="bg-muted border-border"
                onKeyDown={e => e.key === 'Enter' && handleReveal()}
              />
            </div>
            <Button className="w-full" onClick={handleReveal} disabled={loading || !passphrase}>
              {loading ? 'Verifying...' : 'Reveal Secret Key'}
            </Button>
          </div>
        ) : (
          <div className="space-y-4 mt-2">
            <div className="flex items-center gap-2 p-3 bg-muted rounded-lg border border-border">
              <code className="font-mono text-sm text-primary break-all flex-1">{secretKey}</code>
              <Button variant="ghost" size="icon" onClick={handleCopy} className="h-8 w-8 shrink-0">
                {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
              </Button>
            </div>
            <div className="flex items-start gap-2 p-3 bg-destructive/10 rounded-lg border border-destructive/20">
              <ShieldAlert className="h-4 w-4 text-destructive shrink-0 mt-0.5" />
              <p className="text-xs text-destructive">
                Keep this key safe. You need both your passphrase and secret key to access your account.
              </p>
            </div>
            <Button variant="outline" className="w-full" onClick={() => handleOpenChange(false)}>
              Done
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
