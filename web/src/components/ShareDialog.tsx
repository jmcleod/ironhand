import { useCallback, useEffect, useState } from 'react';
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
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Clock, Copy, Check, Link, Loader2, Trash2, UserPlus, Users, X } from 'lucide-react';
import { useToast } from '@/hooks/use-toast';
import type { MemberInfo } from '@/types/vault';
import { isStepUpRequired, type InviteSummary, type CreateInviteResult } from '@/lib/api';
import StepUpAuthDialog from '@/components/StepUpAuthDialog';

interface ShareDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  members: MemberInfo[];
}

function relativeTime(iso: string): string {
  if (!iso) return '';
  const diff = new Date(iso).getTime() - Date.now();
  if (diff <= 0) return 'expired';
  const minutes = Math.floor(diff / 60000);
  if (minutes < 60) return `${minutes}m left`;
  const hours = Math.floor(minutes / 60);
  return `${hours}h left`;
}

function roleBadgeColor(role: string) {
  switch (role) {
    case 'owner': return 'bg-primary/10 text-primary';
    case 'writer': return 'bg-blue-500/10 text-blue-500';
    default: return 'bg-muted text-muted-foreground';
  }
}

export default function ShareDialog({ open, onOpenChange, vaultId, members }: ShareDialogProps) {
  const { revokeMember, changeMemberRole, createInvite, listInvites, cancelInvite, refresh } = useVault();
  const { toast } = useToast();

  const [invites, setInvites] = useState<InviteSummary[]>([]);
  const [inviteLoading, setInviteLoading] = useState(false);
  const [inviteRole, setInviteRole] = useState<string>('reader');
  const [creatingInvite, setCreatingInvite] = useState(false);
  const [createdInvite, setCreatedInvite] = useState<CreateInviteResult | null>(null);
  const [copied, setCopied] = useState(false);
  const [revokeTarget, setRevokeTarget] = useState<string | null>(null);
  const [revokeLoading, setRevokeLoading] = useState(false);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpMethods, setStepUpMethods] = useState<string[]>([]);
  const [stepUpRetry, setStepUpRetry] = useState<(() => void) | null>(null);

  const fetchInvites = useCallback(async () => {
    setInviteLoading(true);
    try {
      const list = await listInvites(vaultId);
      setInvites(list);
    } catch {
      // silently fail
    } finally {
      setInviteLoading(false);
    }
  }, [listInvites, vaultId]);

  useEffect(() => {
    if (open) {
      fetchInvites();
      // Refresh vault context so the members prop is up-to-date (e.g. if
      // someone accepted an invite since the last refresh).
      refresh().catch(() => {});
      setCreatedInvite(null);
      setCopied(false);
    }
  }, [open, fetchInvites, refresh]);

  const handleCreateInvite = async () => {
    setCreatingInvite(true);
    try {
      const result = await createInvite(vaultId, inviteRole);
      setCreatedInvite(result);
      setCopied(false);
      await fetchInvites();
      toast({ title: 'Invite Created', description: 'Share the link and passphrase with the invitee.' });
    } catch (err) {
      if (isStepUpRequired(err)) {
        setStepUpMethods(err.methods);
        setStepUpRetry(() => () => handleCreateInvite());
        setStepUpOpen(true);
        return;
      }
      const msg = (err as { message?: string })?.message ?? 'Failed to create invite.';
      toast({ title: 'Invite Failed', description: msg, variant: 'destructive' });
    } finally {
      setCreatingInvite(false);
    }
  };

  const handleCancelInvite = async (token: string) => {
    try {
      await cancelInvite(vaultId, token);
      setInvites((prev) => prev.filter((i) => i.token !== token));
    } catch {
      toast({ title: 'Failed to cancel invite', variant: 'destructive' });
    }
  };

  const handleCopyInvite = () => {
    if (!createdInvite) return;
    const inviteUrl = `${window.location.origin}${createdInvite.invite_url}`;
    navigator.clipboard.writeText(inviteUrl);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  const handleChangeMemberRole = async (memberID: string, role: string) => {
    try {
      await changeMemberRole(vaultId, memberID, role);
      await refresh();
    } catch (err) {
      if (isStepUpRequired(err)) {
        setStepUpMethods(err.methods);
        setStepUpRetry(() => () => handleChangeMemberRole(memberID, role));
        setStepUpOpen(true);
        return;
      }
      const msg = (err as { message?: string })?.message ?? 'Failed to change role.';
      toast({ title: 'Role Change Failed', description: msg, variant: 'destructive' });
    }
  };

  const handleRevoke = async () => {
    if (!revokeTarget) return;
    setRevokeLoading(true);
    try {
      await revokeMember(vaultId, revokeTarget);
      toast({ title: 'Member Revoked' });
    } catch (err) {
      if (isStepUpRequired(err)) {
        setStepUpMethods(err.methods);
        setStepUpRetry(() => () => handleRevoke());
        setStepUpOpen(true);
        return;
      }
      const msg = (err as { message?: string })?.message ?? 'Failed to revoke member.';
      toast({ title: 'Revoke Failed', description: msg, variant: 'destructive' });
    } finally {
      setRevokeLoading(false);
      setRevokeTarget(null);
    }
  };

  const activeMembers = members.filter((m) => m.status === 'active');

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="bg-card border-border max-w-lg max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Users className="h-5 w-5 text-primary" />
              Share Vault
            </DialogTitle>
          </DialogHeader>
          <div className="space-y-5 mt-2">
            {/* Members list */}
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Members</h3>
              {activeMembers.length === 0 ? (
                <div className="p-3 rounded-lg bg-muted border border-border">
                  <p className="text-sm text-muted-foreground">No members found.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {activeMembers.map((m) => (
                    <div
                      key={m.member_id}
                      className="p-3 rounded-lg bg-muted border border-border flex items-center gap-3"
                    >
                      <div className="flex-1 min-w-0">
                        <p className="text-sm font-mono truncate">{m.member_id}</p>
                        <div className="flex items-center gap-2 mt-1">
                          <span className={`text-xs px-2 py-0.5 rounded-full ${roleBadgeColor(m.role)}`}>
                            {m.role}
                          </span>
                          <span className="text-xs text-muted-foreground">
                            epoch {m.added_epoch}
                          </span>
                        </div>
                      </div>
                      <div className="flex items-center gap-1 shrink-0">
                        <Select
                          value={m.role}
                          onValueChange={(value) => handleChangeMemberRole(m.member_id, value)}
                        >
                          <SelectTrigger className="h-7 w-[90px] text-xs bg-background">
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent className="bg-popover border-border">
                            <SelectItem value="reader">reader</SelectItem>
                            <SelectItem value="writer">writer</SelectItem>
                            <SelectItem value="owner">owner</SelectItem>
                          </SelectContent>
                        </Select>
                        <Button
                          variant="ghost"
                          size="icon"
                          className="h-7 w-7 text-destructive hover:text-destructive"
                          onClick={() => setRevokeTarget(m.member_id)}
                          title="Revoke"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Divider */}
            <div className="relative">
              <div className="absolute inset-0 flex items-center">
                <span className="w-full border-t border-border" />
              </div>
              <div className="relative flex justify-center text-xs uppercase">
                <span className="bg-card px-2 text-muted-foreground">Invites</span>
              </div>
            </div>

            {/* Pending invites list */}
            <div className="space-y-2">
              <h3 className="text-sm font-medium">Pending Invites</h3>
              {inviteLoading ? (
                <div className="flex items-center justify-center py-4">
                  <Loader2 className="h-4 w-4 animate-spin text-muted-foreground" />
                </div>
              ) : invites.length === 0 ? (
                <div className="p-3 rounded-lg bg-muted border border-border">
                  <p className="text-sm text-muted-foreground">No pending invites.</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {invites.map((inv) => (
                    <div
                      key={inv.token}
                      className="p-3 rounded-lg bg-muted border border-border flex items-center gap-3"
                    >
                      <Link className="h-4 w-4 text-muted-foreground shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className={`text-xs px-2 py-0.5 rounded-full ${roleBadgeColor(inv.role)}`}>
                            {inv.role}
                          </span>
                          <span className="text-xs text-muted-foreground flex items-center gap-1">
                            <Clock className="h-3 w-3" />
                            {relativeTime(inv.expires_at)}
                          </span>
                        </div>
                      </div>
                      <Button
                        variant="ghost"
                        size="icon"
                        className="h-7 w-7 text-destructive hover:text-destructive"
                        onClick={() => handleCancelInvite(inv.token)}
                        title="Cancel invite"
                      >
                        <X className="h-3.5 w-3.5" />
                      </Button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Create invite section */}
            <div className="space-y-3">
              <h3 className="text-sm font-medium">Create Invite</h3>
              <div className="flex gap-2">
                <Select value={inviteRole} onValueChange={setInviteRole}>
                  <SelectTrigger className="bg-muted border-border flex-1">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent className="bg-popover border-border">
                    <SelectItem value="reader">reader</SelectItem>
                    <SelectItem value="writer">writer</SelectItem>
                    <SelectItem value="owner">owner</SelectItem>
                  </SelectContent>
                </Select>
                <Button onClick={handleCreateInvite} disabled={creatingInvite}>
                  <UserPlus className="h-4 w-4 mr-2" />
                  {creatingInvite ? 'Creating...' : 'Create Invite'}
                </Button>
              </div>

              {createdInvite && (
                <div className="space-y-2">
                  <div className="p-3 rounded-lg bg-muted border border-border space-y-2">
                    <div>
                      <label className="text-xs font-medium text-muted-foreground">Invite Link</label>
                      <p className="font-mono text-xs break-all mt-0.5">
                        {window.location.origin}{createdInvite.invite_url}
                      </p>
                    </div>
                  </div>
                  <div className="flex items-start gap-2 p-2 rounded bg-yellow-500/10 border border-yellow-500/20">
                    <p className="text-xs text-yellow-600 dark:text-yellow-400">
                      Share this link with the person you want to invite. The invite expires in 1 hour. The passphrase is embedded in the URL fragment and never sent to the server.
                    </p>
                  </div>
                  <Button variant="outline" className="w-full" onClick={handleCopyInvite}>
                    {copied ? (
                      <><Check className="h-4 w-4 mr-2" /> Copied!</>
                    ) : (
                      <><Copy className="h-4 w-4 mr-2" /> Copy Invite Link</>
                    )}
                  </Button>
                </div>
              )}
            </div>
          </div>
        </DialogContent>
      </Dialog>

      {/* Revoke confirmation dialog */}
      <AlertDialog open={!!revokeTarget} onOpenChange={(o) => !o && setRevokeTarget(null)}>
        <AlertDialogContent className="bg-card border-border">
          <AlertDialogHeader>
            <AlertDialogTitle>Revoke Member</AlertDialogTitle>
            <AlertDialogDescription>
              Are you sure you want to revoke this member? This will trigger key rotation and cannot be undone.
            </AlertDialogDescription>
          </AlertDialogHeader>
          <AlertDialogFooter>
            <AlertDialogCancel disabled={revokeLoading}>Cancel</AlertDialogCancel>
            <AlertDialogAction
              onClick={handleRevoke}
              disabled={revokeLoading}
              className="bg-destructive text-destructive-foreground hover:bg-destructive/90"
            >
              {revokeLoading ? 'Revoking...' : 'Revoke'}
            </AlertDialogAction>
          </AlertDialogFooter>
        </AlertDialogContent>
      </AlertDialog>

      <StepUpAuthDialog
        open={stepUpOpen}
        onOpenChange={setStepUpOpen}
        methods={stepUpMethods}
        onVerified={() => {
          if (stepUpRetry) {
            stepUpRetry();
            setStepUpRetry(null);
          }
        }}
      />
    </>
  );
}
