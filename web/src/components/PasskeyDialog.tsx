import { useState } from 'react';
import { Fingerprint } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';

interface PasskeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function PasskeyDialog({ open, onOpenChange }: PasskeyDialogProps) {
  const { account, registerPasskey } = useVault();
  const { toast } = useToast();
  const [loading, setLoading] = useState(false);

  const handleRegister = async () => {
    setLoading(true);
    try {
      await registerPasskey();
      toast({ title: 'Passkey Registered', description: 'Your new passkey is ready to use.' });
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey registration failed';
      toast({ title: 'Registration Failed', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  const credCount = account?.webauthnCredentialCount ?? 0;

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Fingerprint className="h-5 w-5 text-primary" />
            Passkey Management
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          {!account?.webauthnEnabled ? (
            <p className="text-sm text-muted-foreground">
              WebAuthn/passkey support is not available on this server.
            </p>
          ) : (
            <>
              <div className="p-3 rounded-lg bg-muted border border-border">
                <p className="text-sm">
                  {credCount === 0
                    ? 'No passkeys registered. Register a passkey for phishing-resistant sign-in.'
                    : `${credCount} passkey${credCount !== 1 ? 's' : ''} registered.`}
                </p>
              </div>
              <p className="text-xs text-muted-foreground">
                Passkeys replace one-time codes (TOTP) as a second authentication factor.
                Your passphrase and secret key are still required for vault decryption.
              </p>
              <Button className="w-full" onClick={handleRegister} disabled={loading}>
                <Fingerprint className="h-4 w-4 mr-2" />
                {loading ? 'Registering...' : 'Register New Passkey'}
              </Button>
            </>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
