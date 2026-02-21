import { useState } from 'react';
import { Copy, ShieldCheck } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';

interface TwoFactorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function TwoFactorDialog({ open, onOpenChange }: TwoFactorDialogProps) {
  const { account, setupTwoFactor, enableTwoFactor, disableTwoFactor } = useVault();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);
  const [secret, setSecret] = useState('');
  const [otpauthURL, setOtpauthURL] = useState('');
  const [code, setCode] = useState('');
  const [expiresAt, setExpiresAt] = useState('');
  const [disableCode, setDisableCode] = useState('');
  const [disabling, setDisabling] = useState(false);

  const reset = () => {
    setLoading(false);
    setSecret('');
    setOtpauthURL('');
    setCode('');
    setExpiresAt('');
    setDisableCode('');
    setDisabling(false);
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const startSetup = async () => {
    setLoading(true);
    try {
      const out = await setupTwoFactor();
      setSecret(out.secret);
      setOtpauthURL(out.otpauthURL);
      setExpiresAt(out.expiresAt);
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to start 2FA setup';
      toast({ title: '2FA Setup Failed', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  const confirmEnable = async () => {
    setLoading(true);
    try {
      const enabled = await enableTwoFactor(code.trim());
      if (enabled) {
        toast({ title: '2FA Enabled', description: 'One-time code verification is now required on login.' });
        handleOpenChange(false);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Invalid one-time code';
      toast({ title: 'Verification Failed', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={handleOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-primary" />
            Two-Factor Authentication
          </DialogTitle>
        </DialogHeader>
        {account?.twoFactorEnabled ? (
          <div className="space-y-4 mt-2">
            <p className="text-sm text-muted-foreground">
              2FA is enabled for this account. To disable it, enter a current one-time code from your authenticator app.
            </p>
            <Input
              value={disableCode}
              onChange={e => setDisableCode(e.target.value)}
              placeholder="Enter 6-digit one-time code"
              inputMode="numeric"
              className="bg-muted border-border font-mono"
            />
            <Button
              variant="destructive"
              className="w-full"
              disabled={disabling || disableCode.trim().length === 0}
              onClick={async () => {
                setDisabling(true);
                try {
                  const ok = await disableTwoFactor(disableCode.trim());
                  if (ok) {
                    toast({ title: '2FA Disabled', description: 'Two-factor authentication has been turned off.' });
                    handleOpenChange(false);
                  }
                } catch (err) {
                  const message = err instanceof Error ? err.message : (err as { message?: string })?.message ?? 'Invalid one-time code';
                  toast({ title: 'Disable Failed', description: message, variant: 'destructive' });
                } finally {
                  setDisabling(false);
                }
              }}
            >
              {disabling ? 'Disabling...' : 'Disable 2FA'}
            </Button>
          </div>
        ) : !secret ? (
          <div className="space-y-4 mt-2">
            <p className="text-sm text-muted-foreground">
              Generate a TOTP secret and add it to your authenticator app.
            </p>
            <Button className="w-full" onClick={startSetup} disabled={loading}>
              {loading ? 'Generating...' : 'Generate TOTP Secret'}
            </Button>
          </div>
        ) : (
          <div className="space-y-4 mt-2">
            <div className="flex justify-center">
              <img
                src={`https://api.qrserver.com/v1/create-qr-code/?size=220x220&data=${encodeURIComponent(otpauthURL)}`}
                alt="Scan this QR code with your authenticator app"
                className="h-[220px] w-[220px] rounded-lg border border-border bg-white p-2"
              />
            </div>
            <p className="text-xs text-muted-foreground text-center">
              Scan the QR code with your authenticator app, or enter the secret manually.
            </p>
            <div className="space-y-2">
              <p className="text-xs font-medium text-muted-foreground uppercase tracking-wide">TOTP Secret</p>
              <div className="flex items-center gap-2 p-3 rounded-lg bg-muted border border-border">
                <code className="font-mono text-sm break-all flex-1">{secret}</code>
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-8 w-8"
                  onClick={() => navigator.clipboard.writeText(secret)}
                >
                  <Copy className="h-4 w-4" />
                </Button>
              </div>
              <p className="text-xs text-muted-foreground">Expires at {new Date(expiresAt).toLocaleString()}.</p>
            </div>
            <Input
              value={code}
              onChange={e => setCode(e.target.value)}
              placeholder="Enter 6-digit one-time code"
              inputMode="numeric"
              className="bg-muted border-border font-mono"
            />
            <Button className="w-full" onClick={confirmEnable} disabled={loading || code.trim().length === 0}>
              {loading ? 'Verifying...' : 'Enable 2FA'}
            </Button>
          </div>
        )}
      </DialogContent>
    </Dialog>
  );
}
