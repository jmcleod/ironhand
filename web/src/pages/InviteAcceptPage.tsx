import { useEffect, useState } from 'react';
import { useParams, useNavigate } from 'react-router-dom';
import { useVault } from '@/contexts/VaultContext';
import { Button } from '@/components/ui/button';
import { Loader2, Shield, UserPlus } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import logo from '@/assets/logo.png';
import type { InviteInfo } from '@/lib/api';

export default function InviteAcceptPage() {
  const { token } = useParams<{ token: string }>();
  const navigate = useNavigate();
  const { isUnlocked, getInviteInfo, acceptInvite } = useVault();
  const { toast } = useToast();

  const [inviteInfo, setInviteInfo] = useState<InviteInfo | null>(null);
  const [loading, setLoading] = useState(true);
  const [accepting, setAccepting] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Extract passphrase from URL fragment (never sent to server).
  const passphrase = typeof window !== 'undefined' ? window.location.hash.slice(1) : '';

  useEffect(() => {
    if (!token) {
      setError('Invalid invite link.');
      setLoading(false);
      return;
    }
    if (!isUnlocked) {
      setLoading(false);
      return;
    }
    getInviteInfo(token)
      .then((info) => {
        setInviteInfo(info);
        setError(null);
      })
      .catch(() => {
        setError('Invite not found or has expired.');
      })
      .finally(() => setLoading(false));
  }, [token, isUnlocked, getInviteInfo]);

  const handleAccept = async () => {
    if (!token || !passphrase) {
      toast({ title: 'Invalid invite', description: 'Missing token or passphrase.', variant: 'destructive' });
      return;
    }
    setAccepting(true);
    try {
      await acceptInvite(token, passphrase);
      toast({ title: 'Invite Accepted', description: `You now have access to "${inviteInfo?.vault_name}".` });
      navigate('/');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to accept invite.';
      toast({ title: 'Accept Failed', description: msg, variant: 'destructive' });
    } finally {
      setAccepting(false);
    }
  };

  if (!isUnlocked) {
    return (
      <div className="min-h-screen flex items-center justify-center bg-background p-4">
        <div className="w-full max-w-md animate-slide-up">
          <div className="rounded-2xl border border-border bg-card p-8 text-center">
            <img src={logo} alt="Ironhand" className="h-16 w-16 mx-auto mb-6" />
            <h1 className="text-2xl font-bold mb-2">Vault Invite</h1>
            <p className="text-muted-foreground text-sm mb-6">
              You need to log in before accepting this invite.
            </p>
            <Button className="w-full" onClick={() => navigate('/')}>
              Go to Login
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
            <img src={logo} alt="Ironhand" className="h-16 w-16" />
          </div>
          <h1 className="text-2xl font-bold text-center mb-1">Vault Invite</h1>

          {loading ? (
            <div className="flex items-center justify-center py-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : error ? (
            <div className="text-center py-6">
              <p className="text-sm text-destructive mb-4">{error}</p>
              <Button variant="outline" onClick={() => navigate('/')}>
                Go to Dashboard
              </Button>
            </div>
          ) : inviteInfo ? (
            <div className="space-y-4 mt-4">
              <div className="p-4 rounded-lg bg-muted border border-border space-y-3">
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Vault</span>
                  <span className="text-sm font-medium">{inviteInfo.vault_name}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Role</span>
                  <span className="text-sm font-medium capitalize">{inviteInfo.role}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Invited by</span>
                  <span className="text-sm font-mono text-xs truncate max-w-[200px]">{inviteInfo.creator_id}</span>
                </div>
                <div className="flex items-center justify-between">
                  <span className="text-sm text-muted-foreground">Expires</span>
                  <span className="text-sm">{new Date(inviteInfo.expires_at).toLocaleString()}</span>
                </div>
              </div>

              {!passphrase && (
                <div className="p-3 rounded bg-yellow-500/10 border border-yellow-500/20">
                  <p className="text-xs text-yellow-600 dark:text-yellow-400">
                    This invite link appears to be missing the passphrase (URL fragment). Make sure you're using the complete invite link.
                  </p>
                </div>
              )}

              <Button
                className="w-full"
                onClick={handleAccept}
                disabled={accepting || !passphrase}
              >
                <UserPlus className="h-4 w-4 mr-2" />
                {accepting ? 'Accepting...' : 'Accept Invite'}
              </Button>

              <Button variant="ghost" className="w-full" onClick={() => navigate('/')}>
                Cancel
              </Button>

              <div className="flex items-center justify-center gap-2 text-xs text-muted-foreground">
                <Shield className="h-3 w-3" />
                <span>Credentials are encrypted end-to-end</span>
              </div>
            </div>
          ) : null}
        </div>
      </div>
    </div>
  );
}
