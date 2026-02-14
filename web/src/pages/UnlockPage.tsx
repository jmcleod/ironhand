import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Shield } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Checkbox } from '@/components/ui/checkbox';
import { useToast } from '@/hooks/use-toast';
import logo from '@/assets/logo.png';

interface UnlockPageProps {
  onSwitchToRegister: () => void;
}

const SAVED_SECRET_KEY_KEY = 'ironhand_saved_secret_key';

export default function UnlockPage({ onSwitchToRegister }: UnlockPageProps) {
  const { unlock } = useVault();
  const { toast } = useToast();
  const [secretKey, setSecretKey] = useState(() => localStorage.getItem(SAVED_SECRET_KEY_KEY) ?? '');
  const [passphrase, setPassphrase] = useState('');
  const [rememberKey, setRememberKey] = useState(false);
  const [loading, setLoading] = useState(false);

  const handleUnlock = async () => {
    setLoading(true);
    const success = await unlock(secretKey.trim(), passphrase);
    setLoading(false);
    if (!success) {
      toast({ title: 'Login Failed', description: 'Invalid secret key or passphrase.', variant: 'destructive' });
      return;
    }
    if (rememberKey) {
      localStorage.setItem(SAVED_SECRET_KEY_KEY, secretKey.trim());
    } else {
      localStorage.removeItem(SAVED_SECRET_KEY_KEY);
    }
  };

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md animate-slide-up">
        <div className="rounded-2xl border border-border bg-card p-8">
          <div className="flex items-center justify-center mb-6">
            <img src={logo} alt="Ironhand" className="h-16 w-16" />
          </div>
          <h1 className="text-2xl font-bold text-center mb-1">Login</h1>
          <p className="text-muted-foreground text-center text-sm mb-8">Enter passphrase and secret key.</p>

          <div className="space-y-4">
            <Input
              value={secretKey}
              onChange={e => setSecretKey(e.target.value)}
              placeholder="Secret key"
              className="bg-muted border-border font-mono tracking-wider"
            />
            <Input
              type="password"
              value={passphrase}
              onChange={e => setPassphrase(e.target.value)}
              placeholder="Passphrase"
              className="bg-muted border-border"
            />
            <div className="flex items-center gap-2">
              <Checkbox id="remember-key" checked={rememberKey} onCheckedChange={v => setRememberKey(v === true)} />
              <label htmlFor="remember-key" className="text-sm text-muted-foreground">
                Remember secret key on this device
              </label>
            </div>
            <Button className="w-full" onClick={handleUnlock} disabled={loading || !secretKey || !passphrase}>
              {loading ? 'Logging in...' : 'Login'}
            </Button>
            <Button variant="ghost" className="w-full" onClick={onSwitchToRegister}>
              Need an account? Register
            </Button>
          </div>

          <div className="mt-6 flex items-center justify-center gap-2 text-xs text-muted-foreground">
            <Shield className="h-3 w-3" />
            <span>Session secured with HTTP-only cookie</span>
          </div>
        </div>
      </div>
    </div>
  );
}
