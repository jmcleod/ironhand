import { useEffect, useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { Fingerprint, KeyRound, Shield } from 'lucide-react';
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
  const { unlock, unlockWithPasskey } = useVault();
  const { toast } = useToast();
  // Use sessionStorage (not localStorage) so the secret key is cleared when the
  // browser tab/window closes.  This limits the XSS blast radius: an attacker
  // that achieves script execution can only read the key while the tab is open,
  // not after the user has left.
  const [secretKey, setSecretKey] = useState(() => sessionStorage.getItem(SAVED_SECRET_KEY_KEY) ?? '');
  const [passphrase, setPassphrase] = useState('');
  const [totpCode, setTotpCode] = useState('');
  const [recoveryCode, setRecoveryCode] = useState('');
  const [showRecovery, setShowRecovery] = useState(false);
  const [rememberKey, setRememberKey] = useState(false);
  const [loading, setLoading] = useState(false);
  const [passkeyLoading, setPasskeyLoading] = useState(false);

  // One-time migration: clear any secret key previously stored in localStorage
  // by the old implementation to avoid leaving it on disk indefinitely.
  useEffect(() => {
    try { localStorage.removeItem(SAVED_SECRET_KEY_KEY); } catch { /* storage access may be denied */ }
  }, []);

  const handleRememberKey = () => {
    if (rememberKey) {
      sessionStorage.setItem(SAVED_SECRET_KEY_KEY, secretKey.trim());
    } else {
      sessionStorage.removeItem(SAVED_SECRET_KEY_KEY);
    }
  };

  const handleUnlock = async () => {
    setLoading(true);
    try {
      const success = await unlock(
        secretKey.trim(),
        passphrase,
        totpCode,
        showRecovery ? recoveryCode.trim() : undefined,
      );
      if (!success) {
        toast({
          title: 'Login Failed',
          description: 'Invalid credentials or one-time code.',
          variant: 'destructive',
        });
        return;
      }
      handleRememberKey();
    } catch (err) {
      const msg = (err as { message?: string }).message;
      if (msg === 'passkey_required') {
        setShowRecovery(true);
        toast({
          title: 'Passkey Required',
          description: 'Use a passkey or enter a recovery code to sign in.',
          variant: 'destructive',
        });
        return;
      }
      toast({
        title: 'Login Failed',
        description: 'An unexpected error occurred.',
        variant: 'destructive',
      });
    } finally {
      setLoading(false);
    }
  };

  const handlePasskeyLogin = async () => {
    setPasskeyLoading(true);
    const success = await unlockWithPasskey(secretKey.trim(), passphrase);
    setPasskeyLoading(false);
    if (!success) {
      toast({
        title: 'Passkey Login Failed',
        description: 'WebAuthn verification failed or no passkeys registered.',
        variant: 'destructive',
      });
      return;
    }
    handleRememberKey();
  };

  const anyLoading = loading || passkeyLoading;

  return (
    <div className="min-h-screen flex items-center justify-center bg-background p-4">
      <div className="w-full max-w-md animate-slide-up">
        <div className="rounded-2xl border border-border bg-card p-8">
          <div className="flex items-center justify-center mb-6">
            <img src={logo} alt="Ironhand" className="h-16 w-16" />
          </div>
          <h1 className="text-2xl font-bold text-center mb-1">Login</h1>
          <p className="text-muted-foreground text-center text-sm mb-8">Enter passphrase, secret key, and one-time code if enabled.</p>

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
            <Input
              value={totpCode}
              onChange={e => setTotpCode(e.target.value)}
              placeholder="One-time code (if enabled)"
              inputMode="numeric"
              className="bg-muted border-border font-mono"
            />

            {showRecovery && (
              <div className="space-y-2">
                <div className="flex items-center gap-2">
                  <KeyRound className="h-4 w-4 text-yellow-500" />
                  <span className="text-sm font-medium text-yellow-600 dark:text-yellow-400">
                    Recovery Code
                  </span>
                </div>
                <Input
                  value={recoveryCode}
                  onChange={e => setRecoveryCode(e.target.value)}
                  placeholder="xxxx-xxxx-xxxx"
                  className="bg-muted border-border font-mono tracking-wider"
                />
                <p className="text-xs text-muted-foreground">
                  Enter a recovery code to sign in without a passkey. Each code can only be used once.
                </p>
              </div>
            )}

            <div>
              <div className="flex items-center gap-2">
                <Checkbox id="remember-key" checked={rememberKey} onCheckedChange={v => setRememberKey(v === true)} />
                <label htmlFor="remember-key" className="text-sm text-muted-foreground">
                  Remember secret key for this session
                </label>
              </div>
              {rememberKey && (
                <p className="text-xs text-muted-foreground/70 mt-1 ml-6">
                  Key is kept in memory until this tab is closed. It is not written to disk, but could be read by malicious scripts (XSS).
                </p>
              )}
            </div>
            <Button className="w-full" onClick={handleUnlock} disabled={anyLoading || !secretKey || !passphrase}>
              {loading ? 'Logging in...' : showRecovery ? 'Login with Recovery Code' : 'Login'}
            </Button>

            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-border" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">or</span>
              </div>
            </div>

            <Button
              variant="outline"
              className="w-full"
              onClick={handlePasskeyLogin}
              disabled={anyLoading || !secretKey || !passphrase}
            >
              <Fingerprint className="h-4 w-4 mr-2" />
              {passkeyLoading ? 'Verifying passkey...' : 'Sign in with Passkey'}
            </Button>

            {!showRecovery && (
              <button
                type="button"
                className="w-full text-center text-xs text-muted-foreground hover:text-foreground transition-colors"
                onClick={() => setShowRecovery(true)}
              >
                Lost your passkey? Use a recovery code
              </button>
            )}

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
