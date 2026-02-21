import { useCallback, useEffect, useState } from 'react';
import { AlertTriangle, Check, Cloud, Copy, Fingerprint, Loader2, Pencil, Shield, Trash2 } from 'lucide-react';
import { useVault } from '@/contexts/VaultContext';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import {
  AlertDialog,
  AlertDialogAction,
  AlertDialogCancel,
  AlertDialogContent,
  AlertDialogDescription,
  AlertDialogFooter,
  AlertDialogHeader,
  AlertDialogTitle,
} from '@/components/ui/alert-dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import type { PasskeySummary } from '@/lib/api';
import type { ApiError } from '@/lib/api';

interface PasskeyDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

function relativeTime(iso: string): string {
  if (!iso) return '';
  const diff = Date.now() - new Date(iso).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days}d ago`;
  const months = Math.floor(days / 30);
  return `${months}mo ago`;
}

export default function PasskeyDialog({ open, onOpenChange }: PasskeyDialogProps) {
  const { account, registerPasskey, listPasskeys, labelPasskey, deletePasskey, generateRecoveryCodes, updatePasskeyPolicy } = useVault();
  const { toast } = useToast();

  const [passkeys, setPasskeys] = useState<PasskeySummary[]>([]);
  const [loading, setLoading] = useState(false);
  const [registerLoading, setRegisterLoading] = useState(false);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editLabel, setEditLabel] = useState('');
  const [deleteTarget, setDeleteTarget] = useState<PasskeySummary | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);

  const [policyUpdating, setPolicyUpdating] = useState(false);

  // Recovery codes state
  const [recoveryCodes, setRecoveryCodes] = useState<string[] | null>(null);
  const [generatingCodes, setGeneratingCodes] = useState(false);
  const [copied, setCopied] = useState(false);

  const fetchPasskeys = useCallback(async () => {
    setLoading(true);
    try {
      const list = await listPasskeys();
      setPasskeys(list);
    } catch {
      // silently fail — list will be empty
    } finally {
      setLoading(false);
    }
  }, [listPasskeys]);

  useEffect(() => {
    if (open) {
      fetchPasskeys();
      setRecoveryCodes(null);
      setCopied(false);
    }
  }, [open, fetchPasskeys]);

  const handleRegister = async () => {
    setRegisterLoading(true);
    try {
      await registerPasskey();
      toast({ title: 'Passkey Registered', description: 'Your new passkey is ready to use.' });
      await fetchPasskeys();
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Passkey registration failed';
      toast({ title: 'Registration Failed', description: message, variant: 'destructive' });
    } finally {
      setRegisterLoading(false);
    }
  };

  const handleStartEdit = (pk: PasskeySummary) => {
    setEditingId(pk.credential_id);
    setEditLabel(pk.label);
  };

  const handleSaveLabel = async (credentialID: string) => {
    try {
      await labelPasskey(credentialID, editLabel);
      setPasskeys((prev) =>
        prev.map((pk) => (pk.credential_id === credentialID ? { ...pk, label: editLabel } : pk)),
      );
    } catch {
      toast({ title: 'Failed to rename passkey', variant: 'destructive' });
    }
    setEditingId(null);
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    setDeleteLoading(true);
    try {
      await deletePasskey(deleteTarget.credential_id);
      toast({ title: 'Passkey Deleted', description: `"${deleteTarget.label || 'Passkey'}" has been removed.` });
      setPasskeys((prev) => prev.filter((pk) => pk.credential_id !== deleteTarget.credential_id));
    } catch (err) {
      const apiErr = err as ApiError;
      if (apiErr.status === 409) {
        toast({
          title: 'Cannot Delete Last Passkey',
          description: 'Generate recovery codes first to ensure account recovery.',
          variant: 'destructive',
        });
      } else {
        toast({ title: 'Failed to delete passkey', variant: 'destructive' });
      }
    } finally {
      setDeleteLoading(false);
      setDeleteTarget(null);
    }
  };

  const handleGenerateRecoveryCodes = async () => {
    setGeneratingCodes(true);
    try {
      const codes = await generateRecoveryCodes();
      setRecoveryCodes(codes);
      setCopied(false);
      toast({ title: 'Recovery Codes Generated', description: 'Save these codes in a safe place.' });
    } catch {
      toast({ title: 'Failed to generate recovery codes', variant: 'destructive' });
    } finally {
      setGeneratingCodes(false);
    }
  };

  const handleCopyCodes = () => {
    if (!recoveryCodes) return;
    navigator.clipboard.writeText(recoveryCodes.join('\n'));
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const recoveryCodesUnused = account?.recoveryCodesUnused ?? 0;

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="bg-card border-border max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Fingerprint className="h-5 w-5 text-primary" />
              Passkey Management
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-5 mt-2">
            {!account?.webauthnEnabled ? (
              <p className="text-sm text-muted-foreground">
                WebAuthn/passkey support is not available on this server.
              </p>
            ) : (
              <>
                {/* Passkey list */}
                <div className="space-y-2">
                  <h3 className="text-sm font-medium">Registered Passkeys</h3>
                  {loading ? (
                    <div className="flex items-center justify-center py-4">
                      <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                    </div>
                  ) : passkeys.length === 0 ? (
                    <div className="p-3 rounded-lg bg-muted border border-border">
                      <p className="text-sm text-muted-foreground">
                        No passkeys registered. Register a passkey for phishing-resistant sign-in.
                      </p>
                    </div>
                  ) : (
                    <div className="space-y-2">
                      {passkeys.map((pk) => (
                        <div
                          key={pk.credential_id}
                          className="p-3 rounded-lg bg-muted border border-border flex items-center gap-3"
                        >
                          <Fingerprint className="h-4 w-4 text-muted-foreground shrink-0" />
                          <div className="flex-1 min-w-0">
                            {editingId === pk.credential_id ? (
                              <Input
                                value={editLabel}
                                onChange={(e) => setEditLabel(e.target.value)}
                                onBlur={() => handleSaveLabel(pk.credential_id)}
                                onKeyDown={(e) => {
                                  if (e.key === 'Enter') handleSaveLabel(pk.credential_id);
                                  if (e.key === 'Escape') setEditingId(null);
                                }}
                                className="h-7 text-sm bg-background"
                                maxLength={64}
                                autoFocus
                              />
                            ) : (
                              <p className="text-sm font-medium truncate">
                                {pk.label || 'Unnamed passkey'}
                              </p>
                            )}
                            <div className="flex items-center gap-2 mt-0.5">
                              {pk.created_at && (
                                <span className="text-xs text-muted-foreground">
                                  Created {relativeTime(pk.created_at)}
                                </span>
                              )}
                              {pk.last_used_at && (
                                <span className="text-xs text-muted-foreground">
                                  &middot; Used {relativeTime(pk.last_used_at)}
                                </span>
                              )}
                              {pk.backup_state && (
                                <span className="text-xs text-muted-foreground flex items-center gap-0.5" title="Synced passkey">
                                  <Cloud className="h-3 w-3" /> Synced
                                </span>
                              )}
                            </div>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7"
                              onClick={() => handleStartEdit(pk)}
                              title="Rename"
                            >
                              <Pencil className="h-3.5 w-3.5" />
                            </Button>
                            <Button
                              variant="ghost"
                              size="icon"
                              className="h-7 w-7 text-destructive hover:text-destructive"
                              onClick={() => setDeleteTarget(pk)}
                              title="Delete"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </Button>
                          </div>
                        </div>
                      ))}
                    </div>
                  )}
                  <Button className="w-full" onClick={handleRegister} disabled={registerLoading}>
                    <Fingerprint className="h-4 w-4 mr-2" />
                    {registerLoading ? 'Registering...' : 'Register New Passkey'}
                  </Button>
                </div>

                {/* Passkey login policy */}
                {passkeys.length > 0 && (
                  <div className="space-y-2">
                    <h3 className="text-sm font-medium">Login Policy</h3>
                    <p className="text-xs text-muted-foreground">
                      Controls whether passkeys are required for login or optional alongside password+TOTP.
                    </p>
                    <select
                      className="w-full rounded-md border border-border bg-muted px-3 py-2 text-sm"
                      value={account?.passkeyPolicy ?? 'required'}
                      disabled={policyUpdating}
                      onChange={async (e) => {
                        setPolicyUpdating(true);
                        try {
                          await updatePasskeyPolicy(e.target.value);
                          toast({
                            title: 'Policy Updated',
                            description: e.target.value === 'required'
                              ? 'Passkeys are now required for login.'
                              : 'Password+TOTP login is now allowed alongside passkeys.',
                          });
                        } catch {
                          toast({ title: 'Failed to update policy', variant: 'destructive' });
                        } finally {
                          setPolicyUpdating(false);
                        }
                      }}
                    >
                      <option value="required">Required — passkeys mandatory for login</option>
                      <option value="optional">Optional — password+TOTP login allowed</option>
                    </select>
                  </div>
                )}

                {/* Divider */}
                <div className="relative">
                  <div className="absolute inset-0 flex items-center">
                    <span className="w-full border-t border-border" />
                  </div>
                  <div className="relative flex justify-center text-xs uppercase">
                    <span className="bg-card px-2 text-muted-foreground">Recovery</span>
                  </div>
                </div>

                {/* Recovery codes section */}
                <div className="space-y-3">
                  <div className="flex items-center gap-2">
                    <Shield className="h-4 w-4 text-muted-foreground" />
                    <h3 className="text-sm font-medium">Recovery Codes</h3>
                  </div>
                  <p className="text-xs text-muted-foreground">
                    Recovery codes let you sign in if you lose access to your passkey.
                    Each code can only be used once.
                  </p>

                  {recoveryCodes ? (
                    /* Show generated codes */
                    <div className="space-y-2">
                      <div className="p-3 rounded-lg bg-muted border border-border">
                        <div className="grid grid-cols-2 gap-1.5">
                          {recoveryCodes.map((code) => (
                            <code key={code} className="text-sm font-mono text-center py-1 px-2 bg-background rounded">
                              {code}
                            </code>
                          ))}
                        </div>
                      </div>
                      <div className="flex items-start gap-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/20">
                        <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0 mt-0.5" />
                        <p className="text-xs text-yellow-600 dark:text-yellow-400">
                          Save these codes now. They will not be shown again.
                        </p>
                      </div>
                      <Button variant="outline" className="w-full" onClick={handleCopyCodes}>
                        {copied ? (
                          <>
                            <Check className="h-4 w-4 mr-2" /> Copied!
                          </>
                        ) : (
                          <>
                            <Copy className="h-4 w-4 mr-2" /> Copy All Codes
                          </>
                        )}
                      </Button>
                    </div>
                  ) : (
                    /* Show status + generate button */
                    <div className="space-y-2">
                      <div className="p-3 rounded-lg bg-muted border border-border">
                        <p className="text-sm">
                          {recoveryCodesUnused > 0
                            ? `${recoveryCodesUnused} of 8 recovery codes remaining.`
                            : 'No recovery codes generated.'}
                        </p>
                      </div>
                      {passkeys.length > 0 && recoveryCodesUnused === 0 && (
                        <div className="flex items-start gap-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/20">
                          <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0 mt-0.5" />
                          <p className="text-xs text-yellow-600 dark:text-yellow-400">
                            You have passkeys but no recovery codes. Generate codes to avoid being locked out.
                          </p>
                        </div>
                      )}
                      <Button
                        variant="outline"
                        className="w-full"
                        onClick={handleGenerateRecoveryCodes}
                        disabled={generatingCodes}
                      >
                        <Shield className="h-4 w-4 mr-2" />
                        {generatingCodes
                          ? 'Generating...'
                          : recoveryCodesUnused > 0
                            ? 'Regenerate Recovery Codes'
                            : 'Generate Recovery Codes'}
                      </Button>
                      {recoveryCodesUnused > 0 && (
                        <p className="text-xs text-muted-foreground/70">
                          Generating new codes will invalidate all existing codes.
                        </p>
                      )}
                    </div>
                  )}
                </div>

                <p className="text-xs text-muted-foreground">
                  Passkeys replace one-time codes (TOTP) as a second authentication factor.
                  Your passphrase and secret key are still required for vault decryption.
                </p>
              </>
            )}
          </div>
        </DialogContent>
      </Dialog>

      {/* Delete confirmation dialog */}
      <AlertDialog open={!!deleteTarget} onOpenChange={(open) => !open && setDeleteTarget(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Delete Passkey</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to delete &ldquo;{deleteTarget?.label || 'Unnamed passkey'}&rdquo;?
              This action cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={deleteLoading}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleDelete}
              disabled={deleteLoading}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {deleteLoading ? 'Deleting...' : 'Delete'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>
    </>
  );
}
