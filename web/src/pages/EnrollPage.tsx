import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Check, CheckCircle2, Copy, Fingerprint, KeyRound, ShieldAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import logo from '@/assets/logo.png';

interface EnrollPageProps {
  onSwitchToLogin: () => void;
}

export default function EnrollPage({ onSwitchToLogin }: EnrollPageProps) {
  const { enroll, completeEnrollment, registerPasskey, account } = useVault();
  const { toast } = useToast();
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [secretKey, setSecretKey] = useState('');
  const [copied, setCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);
  const [passkeyRegistered, setPasskeyRegistered] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);

  const handleRegister = async () => {
    if (!passphrase || passphrase.length < 10) {
      toast({ title: 'Passphrase too short', description: 'Use at least 10 characters.', variant: 'destructive' });
      return;
    }
    if (passphrase !== confirmPassphrase) {
      toast({ title: 'Passphrase mismatch', description: 'Passphrases must match.', variant: 'destructive' });
      return;
    }
    setLoading(true);
    try {
      const out = await enroll(passphrase);
      setSecretKey(out.secretKey);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Registration failed';
      toast({ title: 'Registration failed', description: msg, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  };

  const handleRegisterPasskey = async () => {
    setPasskeyLoading(true);
    try {
      await registerPasskey();
      setPasskeyRegistered(true);
      toast({ title: 'Passkey Registered', description: 'You can now use your passkey to sign in.' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Passkey registration failed';
      toast({ title: 'Passkey Registration Failed', description: msg, variant: 'destructive' });
    } finally {
      setPasskeyLoading(false);
    }
  };

  if (secretKey) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md animate-slide-up">
          <div className="rounded-2xl border border-border bg-card p-8 glow-primary">
            <div className="flex items-center justify-center mb-4">
              <div className="h-16 w-16 rounded-2xl bg-green-500/10 flex items-center justify-center">
                <CheckCircle2 className="h-8 w-8 text-green-500" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-center mb-1">Registration Successful</h2>
            <p className="text-muted-foreground text-center text-sm mb-6">
              Your account has been created. Save your secret key below — you will need it along with your passphrase to log in.
            </p>
            <div className="mb-4">
              <label className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">
                Secret Key
              </label>
              <div className="flex items-center gap-2 p-3 rounded-xl bg-muted border border-border">
                <KeyRound className="h-4 w-4 text-primary shrink-0" />
                <code className="font-mono text-sm text-primary break-all flex-1">{secretKey}</code>
                <button
                  onClick={() => {
                    navigator.clipboard.writeText(secretKey);
                    setCopied(true);
                    setTimeout(() => setCopied(false), 1800);
                  }}
                  className="text-muted-foreground hover:text-primary shrink-0"
                >
                  {copied ? <Check className="h-4 w-4 text-green-500" /> : <Copy className="h-4 w-4" />}
                </button>
              </div>
            </div>
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 mb-6">
              <div className="flex items-start gap-2">
                <ShieldAlert className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                <div className="text-xs text-destructive space-y-1">
                  <p className="font-medium">Store this key securely before continuing.</p>
                  <p>This key will not be shown again. If you lose it, you will not be able to recover your account.</p>
                </div>
              </div>
            </div>
            <div className="flex items-start gap-3 mb-6 p-3 rounded-lg bg-muted/50 border border-border">
              <Checkbox id="ack-key" checked={acknowledged} onCheckedChange={(v) => setAcknowledged(v === true)} className="mt-0.5" />
              <label htmlFor="ack-key" className="text-sm text-muted-foreground cursor-pointer leading-snug">
                I have securely saved my secret key.
              </label>
            </div>

            {/* Optional passkey registration — only show when WebAuthn is configured */}
            {account?.webauthnEnabled && (
              <div className="mb-4">
                {passkeyRegistered ? (
                  <div className="flex items-center justify-center gap-2 p-3 rounded-lg bg-green-500/10 border border-green-500/20 text-sm text-green-600 dark:text-green-400">
                    <Fingerprint className="h-4 w-4" />
                    <span>Passkey registered</span>
                    <Check className="h-4 w-4" />
                  </div>
                ) : (
                  <Button
                    variant="outline"
                    className="w-full"
                    onClick={handleRegisterPasskey}
                    disabled={passkeyLoading || !acknowledged}
                  >
                    <Fingerprint className="h-4 w-4 mr-2" />
                    {passkeyLoading ? 'Registering passkey...' : 'Register a Passkey (optional)'}
                  </Button>
                )}
              </div>
            )}

            <Button className="w-full" disabled={!acknowledged} onClick={completeEnrollment}>
              Continue to Dashboard
            </Button>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md animate-slide-up">
        <div className="rounded-2xl border border-border bg-card p-8">
          <div className="flex items-center justify-center mb-6">
            <img src={logo} alt="Ironhand" className="h-16 w-16 animate-pulse-glow" />
          </div>
          <h1 className="text-2xl font-bold text-center mb-1">Register</h1>
          <p className="text-muted-foreground text-center text-sm mb-8">Create your IronHand account.</p>
          <div className="space-y-4">
            <Input type="password" value={passphrase} onChange={(e) => setPassphrase(e.target.value)} placeholder="Passphrase" className="bg-muted border-border" />
            <Input
              type="password"
              value={confirmPassphrase}
              onChange={(e) => setConfirmPassphrase(e.target.value)}
              placeholder="Confirm passphrase"
              className="bg-muted border-border"
            />
            <Button className="w-full" onClick={handleRegister} disabled={loading || !passphrase || !confirmPassphrase}>
              {loading ? 'Registering...' : 'Register'}
            </Button>
            <Button variant="ghost" className="w-full" onClick={onSwitchToLogin}>
              Already have an account? Login
            </Button>
          </div>
        </div>
      </div>
    </div>
  );
}
