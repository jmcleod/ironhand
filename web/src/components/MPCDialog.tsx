import { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, CheckCircle2, Clipboard, KeyRound, Loader2, Play, RadioTower, ShieldCheck, UsersRound } from 'lucide-react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Label } from '@/components/ui/label';
import { Textarea } from '@/components/ui/textarea';
import { Badge } from '@/components/ui/badge';
import { Alert, AlertDescription, AlertTitle } from '@/components/ui/alert';
import { Progress } from '@/components/ui/progress';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { useToast } from '@/hooks/use-toast';
import type { MemberInfo } from '@/types/vault';
import {
  abortMPCDKGAttempt,
  approveMPCSigningSession,
  completeMPCSigningSession,
  createMPCKey,
  createMPCSigningSession,
  isStepUpRequired,
  listMPCDKGAttempts,
  listMPCKeys,
  listMPCProviders,
  registerMPCSigner,
  rotateMPCKey,
  updateMPCKeyStatus,
  type MPCDKGAttempt,
  type MPCKey,
  type MPCProviderInfo,
  type MPCSigningSession,
} from '@/lib/api';
import StepUpAuthDialog from '@/components/StepUpAuthDialog';

interface MPCDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  members: MemberInfo[];
  onChanged?: () => void;
}

type WorkflowPhase = 'idle' | 'dkg' | 'session' | 'approvals' | 'complete';

const statusClass: Record<string, string> = {
  active: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/30',
  disabled: 'bg-amber-500/10 text-amber-700 border-amber-500/30',
  archived: 'bg-slate-500/10 text-slate-700 border-slate-500/30',
  rotation_required: 'bg-orange-500/10 text-orange-700 border-orange-500/30',
  reshare_required: 'bg-red-500/10 text-red-700 border-red-500/30',
  destroyed: 'bg-zinc-500/10 text-zinc-700 border-zinc-500/30',
  committed: 'bg-emerald-500/10 text-emerald-700 border-emerald-500/30',
  failed: 'bg-red-500/10 text-red-700 border-red-500/30',
  aborted: 'bg-zinc-500/10 text-zinc-700 border-zinc-500/30',
  started: 'bg-blue-500/10 text-blue-700 border-blue-500/30',
  finalizing: 'bg-indigo-500/10 text-indigo-700 border-indigo-500/30',
  unregistered: 'bg-muted text-muted-foreground border-border',
};

function shortID(value?: string, len = 14) {
  if (!value) return 'not set';
  return value.length > len ? `${value.slice(0, len)}...` : value;
}

function signerCommand(member: MemberInfo) {
  return `ironhand signer --member-id ${member.member_id} --party-id ${member.mpc_party_id || '<party-id>'} --state-file ./signer-${member.mpc_party_id || 'N'}.sealed --mpc-shared-key "$IRONHAND_MPC_SHARED_KEY" --operator-token "$IRONHAND_MPC_SIGNER_OPERATOR_TOKEN"`;
}

export default function MPCDialog({ open, onOpenChange, vaultId, members, onChanged }: MPCDialogProps) {
  const { toast } = useToast();
  const [keys, setKeys] = useState<MPCKey[]>([]);
  const [providers, setProviders] = useState<MPCProviderInfo[]>([]);
  const [dkgAttempts, setDKGAttempts] = useState<MPCDKGAttempt[]>([]);
  const [loading, setLoading] = useState(false);
  const [busy, setBusy] = useState(false);
  const [phase, setPhase] = useState<WorkflowPhase>('idle');
  const [threshold, setThreshold] = useState(2);
  const [selectedMemberIDs, setSelectedMemberIDs] = useState<string[]>([]);
  const [signerMemberID, setSignerMemberID] = useState('');
  const [signerURL, setSignerURL] = useState('');
  const [encPub, setEncPub] = useState('');
  const [approvalPub, setApprovalPub] = useState('');
  const [selectedKeyID, setSelectedKeyID] = useState('');
  const [message, setMessage] = useState('hello from IronHand MPC');
  const [session, setSession] = useState<MPCSigningSession | null>(null);
  const [stepUpOpen, setStepUpOpen] = useState(false);
  const [stepUpMethods, setStepUpMethods] = useState<string[]>([]);
  const [stepUpRetry, setStepUpRetry] = useState<(() => void) | null>(null);

  const activeMembers = useMemo(() => members.filter((m) => m.status === 'active'), [members]);
  const mpcMembers = useMemo(() => activeMembers.filter((m) => m.mpc_signer_status === 'active'), [activeMembers]);
  const unregisteredMembers = useMemo(() => activeMembers.filter((m) => m.mpc_signer_status !== 'active'), [activeMembers]);
  const selectedKey = keys.find((k) => k.key_id === selectedKeyID) ?? keys[0];
  const selectedSignerMember = activeMembers.find((m) => m.member_id === signerMemberID);
  const readiness = activeMembers.length === 0 ? 0 : Math.round((mpcMembers.length / activeMembers.length) * 100);
  const phaseProgress = phase === 'idle' ? 0 : phase === 'dkg' ? 30 : phase === 'session' ? 50 : phase === 'approvals' ? 75 : 100;

  const loadMPCState = useCallback(async () => {
    setLoading(true);
    try {
      const [next, nextProviders, nextDKG] = await Promise.all([
        listMPCKeys(vaultId),
        listMPCProviders(vaultId),
        listMPCDKGAttempts(vaultId),
      ]);
      setKeys(next);
      setProviders(nextProviders);
      setDKGAttempts(nextDKG);
      if (!selectedKeyID && next[0]) setSelectedKeyID(next[0].key_id);
    } catch (err) {
      toast({ title: 'MPC unavailable', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [selectedKeyID, toast, vaultId]);

  useEffect(() => {
    if (open) void loadMPCState();
  }, [open, loadMPCState]);

  const runStepUp = (fn: () => void, err: unknown) => {
    if (isStepUpRequired(err)) {
      setStepUpMethods(err.methods);
      setStepUpRetry(() => fn);
      setStepUpOpen(true);
      return true;
    }
    return false;
  };

  const handleRegisterSigner = async () => {
    const run = () => void handleRegisterSigner();
    setBusy(true);
    try {
      await registerMPCSigner(vaultId, signerMemberID, {
        url: signerURL.trim(),
        encryption_public_key: encPub.trim(),
        approval_public_key: approvalPub.trim(),
        status: 'active',
      });
      toast({ title: 'Signer registered', description: 'The member is now eligible for threshold keys.' });
      setSignerURL('');
      setEncPub('');
      setApprovalPub('');
      onChanged?.();
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Register failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const handleCreateKey = async () => {
    const run = () => void handleCreateKey();
    setBusy(true);
    setPhase('dkg');
    try {
      const key = await createMPCKey(vaultId, { threshold, member_ids: selectedMemberIDs });
      setKeys((prev) => [key, ...prev]);
      setSelectedKeyID(key.key_id);
      void loadMPCState();
      toast({ title: 'MPC key created', description: `${key.threshold} of ${key.participants.length} threshold key is ready.` });
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Key creation failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setPhase('idle');
      setBusy(false);
    }
  };

  const handleSign = async () => {
    if (!selectedKey) return;
    const run = () => void handleSign();
    setBusy(true);
    setPhase('session');
    try {
      let next = await createMPCSigningSession(vaultId, selectedKey.key_id, { message });
      setSession(next);
      setPhase('approvals');
      for (const party of next.participants) {
        next = await approveMPCSigningSession(vaultId, next.session_id, party);
        setSession(next);
      }
      toast({ title: 'Approval requests sent', description: 'Approve each request on its signer, then complete the session.' });
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Signing failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setPhase('idle');
      setBusy(false);
    }
  };

  const handleComplete = async () => {
    if (!session) return;
    const run = () => void handleComplete();
    setBusy(true);
    setPhase('complete');
    try {
      const next = await completeMPCSigningSession(vaultId, session.session_id);
      setSession(next);
      toast({ title: 'MPC signature complete', description: `${next.approvals?.length ?? 0} signer approvals were combined.` });
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Completion failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setPhase('idle');
      setBusy(false);
    }
  };

  const handleKeyStatus = async (keyID: string, status: string) => {
    const run = () => void handleKeyStatus(keyID, status);
    setBusy(true);
    try {
      const updated = await updateMPCKeyStatus(vaultId, keyID, status);
      setKeys((prev) => prev.map((key) => key.key_id === updated.key_id ? updated : key));
      toast({ title: 'MPC key updated', description: `${shortID(keyID)} is now ${status}.` });
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Status update failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const handleAbortDKG = async (dkgSessionID: string) => {
    const run = () => void handleAbortDKG(dkgSessionID);
    setBusy(true);
    try {
      const updated = await abortMPCDKGAttempt(vaultId, dkgSessionID);
      setDKGAttempts((prev) => prev.map((attempt) => attempt.dkg_session_id === updated.dkg_session_id ? updated : attempt));
      toast({ title: 'DKG aborted', description: shortID(dkgSessionID) });
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Abort failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setBusy(false);
    }
  };

  const handleRotateKey = async (keyID: string) => {
    const run = () => void handleRotateKey(keyID);
    setBusy(true);
    setPhase('dkg');
    try {
      const replacement = await rotateMPCKey(vaultId, keyID);
      toast({ title: 'Replacement key created', description: `${shortID(replacement.key_id)} replaced ${shortID(keyID)}.` });
      await loadMPCState();
      setSelectedKeyID(replacement.key_id);
    } catch (err) {
      if (!runStepUp(run, err)) toast({ title: 'Rotation failed', description: (err as Error).message, variant: 'destructive' });
    } finally {
      setPhase('idle');
      setBusy(false);
    }
  };

  const toggleMember = (memberID: string) => {
    setSelectedMemberIDs((prev) => prev.includes(memberID) ? prev.filter((id) => id !== memberID) : [...prev, memberID]);
  };

  const copyCommand = async () => {
    if (!selectedSignerMember) return;
    await navigator.clipboard.writeText(signerCommand(selectedSignerMember));
    toast({ title: 'Signer command copied' });
  };

  return (
    <>
      <Dialog open={open} onOpenChange={onOpenChange}>
        <DialogContent className="bg-card border-border max-w-5xl max-h-[90vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2"><KeyRound className="h-5 w-5 text-primary" /> MPC Vault</DialogTitle>
          </DialogHeader>

          <Alert className="border-amber-500/40 bg-amber-500/5">
            <AlertTriangle className="h-4 w-4 text-amber-600" />
            <AlertTitle>Experimental threshold signing</AlertTitle>
            <AlertDescription>
              This flow uses experimental-p256-schnorr-v1 and must be explicitly enabled on the server. DKG attempts are abortable, approvals are bound to one vault session and expiry, and completion uses a threshold approval subset.
            </AlertDescription>
          </Alert>

          <div className="grid gap-3 md:grid-cols-3">
            <div className="rounded-xl border border-border bg-muted/20 p-4">
              <div className="flex items-center justify-between text-sm"><span className="text-muted-foreground">Signer readiness</span><Badge variant="outline">{mpcMembers.length}/{activeMembers.length}</Badge></div>
              <Progress value={readiness} className="mt-3 h-2" />
            </div>
            <div className="rounded-xl border border-border bg-muted/20 p-4">
              <div className="text-sm text-muted-foreground">Threshold keys</div>
              <div className="mt-2 text-2xl font-semibold">{keys.length}</div>
            </div>
            <div className="rounded-xl border border-border bg-muted/20 p-4">
              <div className="text-sm text-muted-foreground">Current session</div>
              <div className="mt-2 flex items-center gap-2 text-sm"><CheckCircle2 className="h-4 w-4 text-emerald-500" /> {session?.status ?? 'none'}</div>
            </div>
          </div>

          {busy ? <Progress value={phaseProgress} className="h-2" /> : null}

          {loading ? <p className="text-sm text-muted-foreground">Loading MPC state...</p> : (
            <Tabs defaultValue="signers" className="mt-2">
              <TabsList className="grid w-full grid-cols-5">
                <TabsTrigger value="providers"><ShieldCheck className="mr-2 h-4 w-4" /> Providers</TabsTrigger>
                <TabsTrigger value="signers"><RadioTower className="mr-2 h-4 w-4" /> Signers</TabsTrigger>
                <TabsTrigger value="keys"><UsersRound className="mr-2 h-4 w-4" /> Keys</TabsTrigger>
                <TabsTrigger value="dkg"><Loader2 className="mr-2 h-4 w-4" /> DKG</TabsTrigger>
                <TabsTrigger value="sessions"><Play className="mr-2 h-4 w-4" /> Sessions</TabsTrigger>
              </TabsList>

              <TabsContent value="providers" className="space-y-3">
                {providers.length === 0 ? <p className="text-sm text-muted-foreground">No MPC providers reported by the API.</p> : providers.map((provider) => (
                  <section key={provider.algorithm} className="rounded-xl border border-border bg-muted/20 p-4">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <h3 className="text-sm font-semibold">{provider.algorithm}</h3>
                        <p className="text-xs text-muted-foreground">{provider.curve} · {provider.domain || 'no domain metadata'}</p>
                      </div>
                      <Badge variant="outline" className={provider.production_ready ? statusClass.active : statusClass.disabled}>
                        {provider.production_ready ? 'production ready' : 'experimental'}
                      </Badge>
                    </div>
                    <div className="mt-3 grid gap-2 md:grid-cols-3">
                      <Badge variant="outline">keygen {provider.supports_keygen ? 'yes' : 'no'}</Badge>
                      <Badge variant="outline">signing {provider.supports_signing ? 'yes' : 'no'}</Badge>
                      <Badge variant="outline">reshare {provider.supports_reshare ? 'yes' : 'no'}</Badge>
                    </div>
                  </section>
                ))}
              </TabsContent>

              <TabsContent value="signers" className="space-y-4">
                <div className="grid gap-4 md:grid-cols-[1.15fr_0.85fr]">
                  <section className="space-y-3 rounded-xl border border-border bg-muted/20 p-4">
                    <h3 className="text-sm font-semibold">Register signer identity</h3>
                    <Label>Member</Label>
                    <select className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" value={signerMemberID} onChange={(e) => setSignerMemberID(e.target.value)}>
                      <option value="">Choose member</option>
                      {activeMembers.map((m) => <option key={m.member_id} value={m.member_id}>{shortID(m.member_id, 18)} party {m.mpc_party_id || '?'}</option>)}
                    </select>
                    <div className="grid gap-2 md:grid-cols-[1fr_auto]">
                      <Input placeholder="Signer URL, e.g. https://signer-1.internal:8081" value={signerURL} onChange={(e) => setSignerURL(e.target.value)} />
                      <Button variant="outline" disabled={!selectedSignerMember} onClick={copyCommand}><Clipboard className="mr-2 h-4 w-4" /> Copy cmd</Button>
                    </div>
                    <Input placeholder="Encryption public key printed by ironhand signer" value={encPub} onChange={(e) => setEncPub(e.target.value)} />
                    <Input placeholder="Approval public key printed by ironhand signer" value={approvalPub} onChange={(e) => setApprovalPub(e.target.value)} />
                    <Button disabled={busy || !signerMemberID || !signerURL || !encPub || !approvalPub} onClick={handleRegisterSigner}>Register signer</Button>
                  </section>

                  <section className="space-y-3 rounded-xl border border-border bg-muted/20 p-4">
                    <h3 className="text-sm font-semibold">Member signer status</h3>
                    <div className="space-y-2 max-h-72 overflow-auto pr-1">
                      {activeMembers.map((m) => (
                        <div key={m.member_id} className="rounded-lg border border-border bg-background/60 p-3 text-xs">
                          <div className="flex items-center justify-between gap-2">
                            <span className="font-mono">party {m.mpc_party_id || '?'} · {shortID(m.member_id)}</span>
                            <Badge variant="outline" className={statusClass[m.mpc_signer_status || 'unregistered']}>{m.mpc_signer_status || 'unregistered'}</Badge>
                          </div>
                          <div className="mt-1 truncate text-muted-foreground">{m.mpc_signer_url || 'No signer URL registered'}</div>
                        </div>
                      ))}
                    </div>
                    {unregisteredMembers.length > 0 ? <p className="text-xs text-muted-foreground">{unregisteredMembers.length} active member(s) still need signer registration before they can join threshold keys.</p> : null}
                  </section>
                </div>
              </TabsContent>

              <TabsContent value="keys" className="space-y-4">
                <section className="space-y-3 rounded-xl border border-border bg-muted/20 p-4">
                  <h3 className="text-sm font-semibold">Create threshold key</h3>
                  <div className="grid gap-3 md:grid-cols-[160px_1fr]">
                    <div>
                      <Label>Threshold</Label>
                      <Input type="number" min={2} max={Math.max(2, selectedMemberIDs.length)} value={threshold} onChange={(e) => setThreshold(Number(e.target.value))} />
                    </div>
                    <div className="space-y-2">
                      <Label>Participants</Label>
                      <div className="grid gap-2 md:grid-cols-2">
                        {mpcMembers.map((m) => (
                          <label key={m.member_id} className="flex items-center gap-2 rounded-lg border border-border bg-background/60 p-3 text-xs font-mono">
                            <input type="checkbox" checked={selectedMemberIDs.includes(m.member_id)} onChange={() => toggleMember(m.member_id)} />
                            party {m.mpc_party_id}: {shortID(m.member_id, 18)}
                          </label>
                        ))}
                      </div>
                    </div>
                  </div>
                  <Button disabled={busy || selectedMemberIDs.length < threshold} onClick={handleCreateKey}>
                    {busy && phase === 'dkg' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />} Run DKG
                  </Button>
                </section>

                <section className="space-y-2 rounded-xl border border-border bg-muted/20 p-4">
                  <h3 className="text-sm font-semibold">Existing keys</h3>
                  {keys.length === 0 ? <p className="text-sm text-muted-foreground">No threshold keys yet.</p> : keys.map((k) => (
                    <button key={k.key_id} onClick={() => setSelectedKeyID(k.key_id)} className={`w-full rounded-lg border p-3 text-left text-xs transition ${selectedKeyID === k.key_id ? 'border-primary bg-primary/5' : 'border-border bg-background/60'}`}>
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-mono">{k.key_id}</span>
                        <div className="flex gap-2">
                          <Badge variant="outline" className={statusClass[k.status] || ''}>{k.status}</Badge>
                          <Badge variant="outline">{k.threshold} of {k.participants.length}</Badge>
                        </div>
                      </div>
                      <div className="mt-1 text-muted-foreground">{k.provider?.status || 'unknown'} · {k.algorithm} · {shortID(k.public_key.encoded, 34)}</div>
                      <div className="mt-3 flex flex-wrap gap-2">
                        <Button type="button" size="sm" variant="outline" disabled={busy || k.status === 'active'} onClick={(e) => { e.stopPropagation(); void handleKeyStatus(k.key_id, 'active'); }}>Enable</Button>
                        <Button type="button" size="sm" variant="outline" disabled={busy || k.status === 'disabled'} onClick={(e) => { e.stopPropagation(); void handleKeyStatus(k.key_id, 'disabled'); }}>Disable</Button>
                        <Button type="button" size="sm" variant="outline" disabled={busy || k.status === 'rotation_required'} onClick={(e) => { e.stopPropagation(); void handleKeyStatus(k.key_id, 'rotation_required'); }}>Rotation needed</Button>
                        <Button type="button" size="sm" variant="outline" disabled={busy || k.status === 'destroyed'} onClick={(e) => { e.stopPropagation(); void handleRotateKey(k.key_id); }}>Create replacement</Button>
                        <Button type="button" size="sm" variant="outline" disabled={busy || k.status === 'archived'} onClick={(e) => { e.stopPropagation(); void handleKeyStatus(k.key_id, 'archived'); }}>Archive</Button>
                      </div>
                      {k.replaces_key_id || k.replaced_by_key_id ? (
                        <div className="mt-2 text-muted-foreground">
                          {k.replaces_key_id ? `replaces ${shortID(k.replaces_key_id)}` : ''}
                          {k.replaced_by_key_id ? ` replaced by ${shortID(k.replaced_by_key_id)}` : ''}
                        </div>
                      ) : null}
                    </button>
                  ))}
                </section>
              </TabsContent>

              <TabsContent value="dkg" className="space-y-3">
                {dkgAttempts.length === 0 ? <p className="text-sm text-muted-foreground">No DKG attempts recorded yet.</p> : dkgAttempts.map((attempt) => (
                  <section key={attempt.dkg_session_id} className="rounded-xl border border-border bg-muted/20 p-4 text-xs">
                    <div className="flex flex-wrap items-center justify-between gap-2">
                      <div>
                        <div className="font-mono">{attempt.key_id}</div>
                        <div className="text-muted-foreground">{shortID(attempt.dkg_session_id, 32)}</div>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={statusClass[attempt.status] || ''}>{attempt.status}</Badge>
                        <Badge variant="outline">{attempt.threshold} threshold</Badge>
                        <Badge variant="outline">{attempt.members?.length ?? 0} members</Badge>
                      </div>
                    </div>
                    {attempt.last_error ? <p className="mt-2 rounded-md border border-red-500/30 bg-red-500/5 p-2 text-red-700">{attempt.last_error}</p> : null}
                    <div className="mt-3 flex gap-2">
                      <Button type="button" size="sm" variant="outline" disabled={busy || ['committed', 'aborted'].includes(attempt.status)} onClick={() => void handleAbortDKG(attempt.dkg_session_id)}>Abort</Button>
                      <Button type="button" size="sm" variant="ghost" onClick={() => void loadMPCState()}>Refresh</Button>
                    </div>
                  </section>
                ))}
              </TabsContent>

              <TabsContent value="sessions" className="space-y-4">
                <section className="space-y-3 rounded-xl border border-border bg-muted/20 p-4">
                  <h3 className="text-sm font-semibold">Create, approve, and complete session</h3>
                  <select className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm" value={selectedKey?.key_id ?? ''} onChange={(e) => setSelectedKeyID(e.target.value)}>
                    {keys.map((k) => <option key={k.key_id} value={k.key_id}>{k.key_id} ({k.threshold} of {k.participants.length})</option>)}
                  </select>
                  <Textarea value={message} onChange={(e) => setMessage(e.target.value)} rows={4} />
                  <Button disabled={busy || !selectedKey || !message} onClick={handleSign}>
                    {busy && phase !== 'dkg' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <Play className="mr-2 h-4 w-4" />} Create and request approvals
                  </Button>
                  <Button variant="outline" disabled={busy || !session || session.status !== 'pending'} onClick={handleComplete}>
                    {busy && phase === 'complete' ? <Loader2 className="mr-2 h-4 w-4 animate-spin" /> : <ShieldCheck className="mr-2 h-4 w-4" />} Complete approved session
                  </Button>
                  {session ? (
                    <div className="rounded-lg border border-border bg-background/60 p-3 text-xs">
                      <div className="flex flex-wrap gap-2">
                        <Badge variant="outline">{session.status}</Badge>
                        <Badge variant="outline">{session.participants.length} participants</Badge>
                        <Badge variant="outline">{session.approvals?.length ?? 0} approvals</Badge>
                        <Badge variant="outline">expires {new Date(session.expires_at).toLocaleTimeString()}</Badge>
                      </div>
                      <div className="mt-2 font-mono text-muted-foreground">{session.session_id}</div>
                    </div>
                  ) : null}
                  {session?.signature ? (
                    <pre className="max-h-64 overflow-auto rounded-lg bg-background p-3 text-xs">{JSON.stringify(session.signature, null, 2)}</pre>
                  ) : null}
                </section>
              </TabsContent>
            </Tabs>
          )}
        </DialogContent>
      </Dialog>
      <StepUpAuthDialog open={stepUpOpen} onOpenChange={setStepUpOpen} methods={stepUpMethods} onVerified={() => { setStepUpOpen(false); stepUpRetry?.(); }} />
    </>
  );
}
