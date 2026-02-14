import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Check, Copy, KeyRound, ShieldAlert } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import logo from '@/assets/logo.png';

interface EnrollPageProps {
  onSwitchToLogin: () => void;
}

export default function EnrollPage({ onSwitchToLogin }: EnrollPageProps) {
  const { enroll } = useVault();
  const { toast } = useToast();
  const [passphrase, setPassphrase] = useState('');
  const [confirmPassphrase, setConfirmPassphrase] = useState('');
  const [loading, setLoading] = useState(false);
  const [secretKey, setSecretKey] = useState('');
  const [copied, setCopied] = useState(false);
  const [acknowledged, setAcknowledged] = useState(false);

  const handleRegister = async () => {
    if (!passphrase || passphrase.length < 8) {
      toast({ title: 'Passphrase too short', description: 'Use at least 8 characters.', variant: 'destructive' });
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

  if (secretKey) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md animate-slide-up">
          <div className="rounded-2xl border border-border bg-card p-8 glow-primary">
            <div className="flex items-center justify-center mb-6">
              <div className="h-16 w-16 rounded-2xl bg-accent flex items-center justify-center">
                <KeyRound className="h-8 w-8 text-accent-foreground" />
              </div>
            </div>
            <h2 className="text-2xl font-bold text-center mb-2">Your Secret Key</h2>
            <p className="text-muted-foreground text-center text-sm mb-6">
              Save this key securely. You will need it with your passphrase to log in.
            </p>
            <div className="flex items-center gap-2 p-3 rounded-xl bg-muted border border-border mb-4">
              <code className="font-mono text-sm text-primary break-all flex-1">{secretKey}</code>
              <button
                onClick={() => {
                  navigator.clipboard.writeText(secretKey);
                  setCopied(true);
                  setTimeout(() => setCopied(false), 1800);
                }}
                className="text-muted-foreground hover:text-primary"
              >
                {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
              </button>
            </div>
            <div className="p-3 rounded-lg bg-destructive/10 border border-destructive/20 mb-6">
              <div className="flex items-start gap-2">
                <ShieldAlert className="h-4 w-4 text-destructive mt-0.5 shrink-0" />
                <p className="text-xs text-destructive">If you lose this key, you cannot recover access.</p>
              </div>
            </div>
            <div className="flex items-start gap-3 mb-6 p-3 rounded-lg bg-muted/50 border border-border">
              <Checkbox id="ack-key" checked={acknowledged} onCheckedChange={(v) => setAcknowledged(v === true)} className="mt-0.5" />
              <label htmlFor="ack-key" className="text-sm text-muted-foreground cursor-pointer leading-snug">
                I have securely saved my secret key.
              </label>
            </div>
            <Button className="w-full" disabled={!acknowledged} onClick={onSwitchToLogin}>
              Continue to Login
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
