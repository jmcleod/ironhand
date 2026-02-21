import { useState } from 'react';
import { Fingerprint, ShieldCheck } from 'lucide-react';
import { startAuthentication } from '@simplewebauthn/browser';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { stepUpTOTP, beginStepUpPasskey, finishStepUpPasskey } from '@/lib/api';

interface StepUpAuthDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  methods: string[];
  onVerified: () => void;
}

export default function StepUpAuthDialog({ open, onOpenChange, methods, onVerified }: StepUpAuthDialogProps) {
  const { toast } = useToast();
  const [code, setCode] = useState('');
  const [loading, setLoading] = useState(false);

  const hasTotp = methods.includes('totp');
  const hasPasskey = methods.includes('passkey');

  const reset = () => {
    setCode('');
    setLoading(false);
  };

  const handleOpenChange = (next: boolean) => {
    if (!next) reset();
    onOpenChange(next);
  };

  const handleTOTP = async () => {
    setLoading(true);
    try {
      await stepUpTOTP(code.trim());
      reset();
      onOpenChange(false);
      onVerified();
    } catch (err) {
      const message = (err as { message?: string })?.message ?? 'Invalid one-time code';
      toast({ title: 'Verification Failed', description: message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  const handlePasskey = async () => {
    setLoading(true);
    try {
      // eslint-disable-next-line @typescript-eslint/no-explicit-any
      const options = (await beginStepUpPasskey()) as any;
      const assertion = await startAuthentication({ optionsJSON: options.publicKey ?? options });
      await finishStepUpPasskey(assertion);
      reset();
      onOpenChange(false);
      onVerified();
    } catch (err) {
      const message = (err as { message?: string })?.message ?? 'Passkey verification failed';
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
            Re-authenticate
          </DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <p className="text-sm text-muted-foreground">
            This action requires re-authentication. Verify your identity to continue.
          </p>

          {hasTotp && (
            <div className="space-y-3">
              <Input
                value={code}
                onChange={e => setCode(e.target.value)}
                placeholder="Enter 6-digit one-time code"
                inputMode="numeric"
                className="bg-muted border-border font-mono"
                onKeyDown={e => {
                  if (e.key === 'Enter' && code.trim().length > 0) handleTOTP();
                }}
              />
              <Button
                className="w-full"
                onClick={handleTOTP}
                disabled={loading || code.trim().length === 0}
              >
                <ShieldCheck className="h-4 w-4 mr-2" />
                {loading ? 'Verifying...' : 'Verify with TOTP'}
              </Button>
            </div>
          )}

          {hasTotp && hasPasskey && (
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-border" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">or</span>
              </div>
            </div>
          )}

          {hasPasskey && (
            <Button
              variant="outline"
              className="w-full"
              onClick={handlePasskey}
              disabled={loading}
            >
              <Fingerprint className="h-4 w-4 mr-2" />
              {loading ? 'Verifying...' : 'Verify with Passkey'}
            </Button>
          )}
        </div>
      </DialogContent>
    </Dialog>
  );
}
