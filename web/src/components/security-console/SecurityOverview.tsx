import { useEffect, useMemo, useState } from 'react';
import {
  AlertTriangle,
  Check,
  Circle,
  Eye,
  FileKey2,
  KeyRound,
  Lock,
  Network,
  RotateCw,
  Shield,
  ShieldCheck,
  UserRoundPlus,
  UserRoundX,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import {
  ConsolePanel,
  ConsolePanelHeader,
  ConsoleTable,
  ConsoleTd,
  ConsoleTh,
  MetricBlock,
  StatusPill,
} from '@/components/security-console/ConsolePrimitives';
import { AuditStatus, getAuditStatus, listAuditLogs } from '@/lib/api';
import { AuditEntry, itemName, itemType, Vault } from '@/types/vault';
import { cn } from '@/lib/utils';
import { riskAlerts, secretHealth } from '@/lib/security-insights';

interface SecurityOverviewProps {
  vault: Vault | null;
  twoFactorEnabled: boolean;
  passkeyCount: number;
  recoveryCodesUnused: number;
  onRotate: () => void;
  onInvite: () => void;
  onRevoke: () => void;
  onIssueCert: () => void;
  onViewCA: () => void;
  onMPC: () => void;
  onAudit: () => void;
  onLock: () => void;
}

function actionLabel(action: AuditEntry['action']) {
  switch (action) {
    case 'item_accessed':
      return 'Read Secret';
    case 'item_created':
      return 'Created Secret';
    case 'item_updated':
      return 'Updated Secret';
    case 'item_deleted':
      return 'Deleted Secret';
    case 'vault_exported':
      return 'Vault Exported';
    case 'vault_imported':
      return 'Vault Imported';
    case 'ca_initialized':
      return 'CA Initialized';
    case 'cert_issued':
      return 'Issue Cert';
    case 'cert_revoked':
      return 'Revoke Cert';
    case 'cert_renewed':
      return 'Renew Cert';
    case 'crl_generated':
      return 'Generate CRL';
    case 'csr_signed':
      return 'Sign CSR';
    case 'private_key_accessed':
      return 'Private Key Read';
  }
}

function memberDisplayName(memberID: string) {
  return memberID.replace(/[_-]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
}

export default function SecurityOverview({
  vault,
  twoFactorEnabled,
  passkeyCount,
  recoveryCodesUnused,
  onRotate,
  onInvite,
  onRevoke,
  onIssueCert,
  onViewCA,
  onMPC,
  onAudit,
  onLock,
}: SecurityOverviewProps) {
  const [auditEntries, setAuditEntries] = useState<AuditEntry[]>([]);
  const [auditStatus, setAuditStatus] = useState<AuditStatus | null>(null);
  const [auditLoading, setAuditLoading] = useState(false);

  useEffect(() => {
    if (!vault) {
      setAuditEntries([]);
      setAuditStatus(null);
      return;
    }
    setAuditLoading(true);
    Promise.all([
      listAuditLogs(vault.id, undefined, { limit: 5, offset: 0 }).catch(() => ({ data: [] as AuditEntry[] })),
      getAuditStatus(vault.id).catch(() => null),
    ])
      .then(([result, status]) => {
        setAuditEntries(result.data);
        setAuditStatus(status);
      })
      .finally(() => setAuditLoading(false));
  }, [vault]);

  const activeMembers = useMemo(
    () => vault?.members.filter((member) => member.status !== 'revoked') ?? [],
    [vault],
  );
  const revokedMembers = useMemo(
    () => vault?.members.filter((member) => member.status === 'revoked') ?? [],
    [vault],
  );
  const mpcSigners = activeMembers.filter((member) => member.mpc_party_id || member.mpc_signer_status);
  const health = useMemo(() => secretHealth(vault), [vault]);
  const alerts = useMemo(() => riskAlerts(vault, auditEntries, auditStatus?.verified ?? auditEntries.length === 0), [vault, auditEntries, auditStatus]);
  const activity = useMemo(() => {
    if (!vault) return [];
    if (auditEntries.length > 0) {
      return auditEntries.slice(0, 6).map((entry) => ({
        id: entry.id,
        title: actionLabel(entry.action),
        detail: entry.item_id || vault.name,
        actor: memberDisplayName(entry.member_id),
        time: new Date(entry.created_at).toLocaleTimeString(),
        tone: entry.action === 'private_key_accessed' ? 'danger' : entry.action === 'vault_exported' ? 'warning' : 'success',
      }));
    }
    return [
      { id: 'live-posture', title: 'Posture evaluated', detail: `${health.score}/100 secret health`, actor: 'Ironhand', time: 'live', tone: health.score >= 85 ? 'success' : 'warning' },
      { id: 'live-members', title: 'Member graph synced', detail: `${activeMembers.length} active members`, actor: 'Ironhand', time: 'live', tone: 'success' },
      { id: 'live-audit', title: 'Audit chain checked', detail: auditVerified ? 'Verified' : 'Awaiting events', actor: 'Ironhand', time: 'live', tone: auditVerified ? 'success' : 'muted' },
    ];
  }, [activeMembers.length, auditEntries, auditVerified, health.score, vault]);
  if (!vault) {
    return (
      <ConsolePanel className="flex min-h-[560px] flex-col items-center justify-center p-8 text-center">
        <Shield className="mb-4 h-12 w-12 text-muted-foreground" />
        <h1 className="mb-2 text-2xl font-semibold">Create a vault to start the console</h1>
        <p className="max-w-md text-sm text-muted-foreground">
          The security overview needs at least one vault before it can show posture, members, audit activity, CA state, or MPC status.
        </p>
      </ConsolePanel>
    );
  }

  const postureStrong = twoFactorEnabled && passkeyCount > 0 && revokedMembers.length === 0 && health.score >= 85;
  const auditVerified = auditStatus?.verified ?? false;

  return (
    <div className="space-y-3">
      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1.25fr_1fr]">
        <ConsolePanel className="p-5">
          <ConsolePanelHeader title="Security Posture" />
          <div className="mt-5 grid gap-6 lg:grid-cols-[180px_minmax(0,1fr)_190px]">
            <div className="relative mx-auto flex h-44 w-44 items-center justify-center rounded-full border border-primary/30 bg-primary/5 console-grid">
              <div className="absolute inset-3 rounded-full border border-primary/20" />
              <div className="absolute inset-8 rounded-full border border-primary/25" />
              <div className="flex h-24 w-24 items-center justify-center rounded-[1.4rem] border border-primary/50 bg-primary/20 shadow-[0_0_45px_hsl(var(--primary)/0.22)]">
                <ShieldCheck className="h-12 w-12 text-primary" />
              </div>
            </div>

            <div className="space-y-3">
              {[
                ['Encryption', 'Strong', true],
                ['Rollback Protection', 'Enabled', true],
                ['Audit Chain', auditVerified ? 'Verified' : auditStatus?.failure_reason ?? 'Awaiting Events', auditVerified],
                ['Secrets Hygiene', health.score >= 85 ? 'Strong' : health.score >= 70 ? 'Review' : 'At Risk', health.score >= 85],
              ].map(([label, value, good]) => (
                <div key={String(label)} className="flex items-center justify-between rounded-full border border-border bg-muted/30 px-4 py-2">
                  <span className="flex items-center gap-2 text-sm">
                    <ShieldCheck className={cn('h-4 w-4', good ? 'text-primary' : 'text-amber-400')} />
                    {label}
                  </span>
                  <span className={cn('text-sm font-semibold', good ? 'text-primary' : 'text-amber-400')}>{value}</span>
                </div>
              ))}
              <div className="grid gap-2 sm:grid-cols-3">
                <Button variant="outline" onClick={onRotate}>
                  <RotateCw className="h-4 w-4" />
                  Rotate
                </Button>
                <Button variant="outline" onClick={onAudit}>
                  <ShieldCheck className="h-4 w-4" />
                  Verify Audit
                </Button>
                <Button variant="outline" onClick={onLock}>
                  <Lock className="h-4 w-4" />
                  Lock Session
                </Button>
              </div>
            </div>

            <div className="divide-y divide-border/70 border-l border-border/70 pl-6">
              <MetricBlock label="Encryption Epoch" value={vault.epoch} detail={`Vault ${vault.name}`} tone="success" className="pb-4" />
              <MetricBlock label="Secret Health" value={health.score} detail={`${health.issues.length} issue${health.issues.length === 1 ? '' : 's'} tracked`} tone={health.score >= 85 ? 'success' : health.score >= 70 ? 'warning' : 'danger'} className="py-4" />
              <MetricBlock label="Active Members" value={activeMembers.length} detail={`${vault.members.length} total`} className="py-4" />
              <MetricBlock label="Revoked Members" value={revokedMembers.length} tone={revokedMembers.length > 0 ? 'danger' : 'success'} className="pt-4" />
            </div>
          </div>
        </ConsolePanel>

        <ConsolePanel className="p-5">
          <ConsolePanelHeader
            title="Vault Access Graph"
            action={<StatusPill tone="muted">Live</StatusPill>}
          />
          <div className="relative mt-5 min-h-[250px] overflow-hidden rounded-lg border border-border/70 bg-muted/20">
            <svg viewBox="0 0 560 260" className="absolute inset-0 h-full w-full">
              <line x1="280" y1="130" x2="280" y2="42" stroke="hsl(var(--border))" />
              <line x1="280" y1="130" x2="460" y2="80" stroke="hsl(var(--border))" />
              <line x1="280" y1="130" x2="450" y2="205" stroke="hsl(var(--border))" />
              <line x1="280" y1="130" x2="100" y2="80" stroke="hsl(var(--border))" />
              <line x1="280" y1="130" x2="110" y2="205" stroke="hsl(var(--border))" />
              <circle cx="280" cy="42" r="4" fill="hsl(var(--primary))" />
              <circle cx="460" cy="80" r="4" fill="hsl(var(--primary))" />
              <circle cx="450" cy="205" r="4" fill="hsl(var(--primary))" />
              <circle cx="100" cy="80" r="4" fill="hsl(var(--primary))" />
              <circle cx="110" cy="205" r="4" fill="hsl(var(--primary))" />
            </svg>
            <div className="absolute left-1/2 top-1/2 flex h-20 w-20 -translate-x-1/2 -translate-y-1/2 flex-col items-center justify-center rounded-xl border border-primary bg-primary/10 text-center shadow-[0_0_35px_hsl(var(--primary)/0.18)]">
              <Lock className="mb-1 h-6 w-6 text-primary" />
              <span className="text-xs font-semibold">{vault.name}</span>
            </div>
            {[
              ['Apps', vault.items.filter((item) => itemType(item) === 'login').length, 'left-[47%] top-5'],
              ['Users', activeMembers.length, 'right-8 top-16'],
              ['Services', vault.items.filter((item) => itemType(item) === 'custom').length, 'left-8 top-16'],
              ['Certificates', vault.items.filter((item) => itemType(item) === 'certificate').length, 'right-10 bottom-8'],
              ['MPC', mpcSigners.length, 'left-10 bottom-8'],
            ].map(([label, value, position]) => (
              <div key={String(label)} className={cn('absolute flex items-center gap-2', position)}>
                <span className="flex h-9 w-9 items-center justify-center rounded-full border border-primary/30 bg-primary/10">
                  <Circle className="h-4 w-4 text-primary" />
                </span>
                <span className="text-sm">
                  <span className="block font-semibold">{label}</span>
                  <span className="text-muted-foreground">{value}</span>
                </span>
              </div>
            ))}
          </div>
        </ConsolePanel>
      </div>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[1fr_0.9fr_1.15fr]">
        <ConsolePanel className="p-5">
          <ConsolePanelHeader title="Member Roles" />
          <ConsoleTable className="mt-4">
            <thead>
              <tr>
                <ConsoleTh>Member</ConsoleTh>
                <ConsoleTh>Admin</ConsoleTh>
                <ConsoleTh>Editor</ConsoleTh>
                <ConsoleTh>Viewer</ConsoleTh>
                <ConsoleTh>MPC</ConsoleTh>
                <ConsoleTh>Status</ConsoleTh>
              </tr>
            </thead>
            <tbody>
              {vault.members.slice(0, 5).map((member) => {
                const owner = member.role === 'owner';
                const writer = owner || member.role === 'writer';
                const reader = writer || member.role === 'reader';
                return (
                  <tr key={member.member_id}>
                    <ConsoleTd className="font-medium">{memberDisplayName(member.member_id)}</ConsoleTd>
                    {[owner, writer, reader, !!member.mpc_party_id].map((enabled, index) => (
                      <ConsoleTd key={index} className={enabled ? 'text-primary' : 'text-muted-foreground'}>{enabled ? <Check className="h-4 w-4" /> : '-'}</ConsoleTd>
                    ))}
                    <ConsoleTd>
                      <StatusPill tone={member.status === 'revoked' ? 'danger' : 'success'}>
                        {member.status}
                      </StatusPill>
                    </ConsoleTd>
                  </tr>
                );
              })}
            </tbody>
          </ConsoleTable>
          <div className="mt-4 grid grid-cols-3 gap-2">
            <Button variant="outline" onClick={onInvite}>
              <UserRoundPlus className="h-4 w-4" />
              Invite
            </Button>
            <Button variant="outline" onClick={onRevoke}>
              <UserRoundX className="h-4 w-4" />
              Revoke
            </Button>
            <Button variant="outline" onClick={onInvite}>Manage Roles</Button>
          </div>
        </ConsolePanel>

        <ConsolePanel className="p-5">
          <ConsolePanelHeader title="Certificate Authority" />
          <div className="mt-4 space-y-3">
            <div className="flex items-center justify-between rounded-lg border border-border bg-muted/30 p-3">
              <div className="flex min-w-0 items-center gap-3">
                <span className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10">
                  <Shield className="h-5 w-5 text-primary" />
                </span>
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold">{vault.isCA ? `${vault.name} CA` : 'No CA initialized'}</p>
                  <p className="text-xs text-muted-foreground">{vault.isCA ? 'Root authority active' : 'Initialize this vault as a CA'}</p>
                </div>
              </div>
              <StatusPill tone={vault.isCA ? 'success' : 'warning'}>{vault.isCA ? 'Active' : 'Not set'}</StatusPill>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <div className="console-panel-subtle rounded-lg p-3">
                <p className="console-kicker mb-1">Certificates</p>
                <p className="text-2xl font-semibold">{vault.items.filter((item) => itemType(item) === 'certificate').length}</p>
              </div>
              <div className="console-panel-subtle rounded-lg p-3">
                <p className="console-kicker mb-1">Mode</p>
                <p className="text-sm font-semibold">{vault.isCA ? 'Issuing' : 'Vault only'}</p>
              </div>
            </div>
            <div className="grid grid-cols-2 gap-2">
              <Button variant="outline" onClick={onIssueCert}>
                <FileKey2 className="h-4 w-4" />
                Issue Cert
              </Button>
              <Button variant="outline" onClick={onViewCA}>
                <Eye className="h-4 w-4" />
                View CA
              </Button>
            </div>
          </div>
        </ConsolePanel>

        <ConsolePanel className="p-5">
          <ConsolePanelHeader
            title="MPC Signing Queue"
            action={<StatusPill tone={mpcSigners.length > 0 ? 'success' : 'muted'}>{mpcSigners.length || 0} signer{mpcSigners.length === 1 ? '' : 's'}</StatusPill>}
          />
          <div className="mt-4 space-y-2">
            {mpcSigners.length === 0 ? (
              <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
                No MPC signers are configured for this vault yet.
              </div>
            ) : (
              mpcSigners.slice(0, 3).map((member) => (
                <div key={member.member_id} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/25 p-3">
                  <div className="min-w-0">
                    <p className="truncate text-sm font-semibold">Signer {member.mpc_party_id ?? member.member_id}</p>
                    <p className="truncate text-xs text-muted-foreground">{member.mpc_signer_url ?? member.member_id}</p>
                  </div>
                  <Button variant="outline" size="sm" onClick={onMPC}>
                    <KeyRound className="h-4 w-4" />
                    Sign MPC
                  </Button>
                </div>
              ))
            )}
          </div>
        </ConsolePanel>
      </div>

      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Live Security Activity" action={<StatusPill tone="success">Live</StatusPill>} />
        <div className="mt-4 grid gap-2 xl:grid-cols-3">
          {activity.map((event) => (
            <div key={event.id} className="rounded-lg border border-border bg-muted/25 p-3">
              <div className="flex items-center justify-between gap-3">
                <p className="truncate text-sm font-semibold">{event.title}</p>
                <StatusPill tone={event.tone as 'success' | 'warning' | 'danger' | 'muted'}>{event.time}</StatusPill>
              </div>
              <p className="mt-1 truncate text-xs text-muted-foreground">{event.detail}</p>
              <p className="mt-2 text-xs text-muted-foreground">{event.actor}</p>
            </div>
          ))}
        </div>
      </ConsolePanel>

      <div className="grid grid-cols-1 gap-3 xl:grid-cols-[0.85fr_1.95fr]">
        <ConsolePanel className="p-5">
          <ConsolePanelHeader
            title="Risk Alerts"
            action={alerts.length > 0 ? <StatusPill tone="danger">{alerts.length}</StatusPill> : <StatusPill tone="success">0</StatusPill>}
          />
          <div className="mt-4 space-y-2">
            {alerts.length === 0 ? (
              <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
                No risk alerts are active for this vault.
              </div>
            ) : alerts.slice(0, 3).map((alert) => (
              <div key={alert.id} className="rounded-lg border border-border bg-muted/25 p-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="truncate text-sm font-semibold">{alert.title}</p>
                  <StatusPill tone={alert.severity === 'critical' || alert.severity === 'high' ? 'danger' : 'warning'}>{alert.severity}</StatusPill>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{alert.detail}</p>
              </div>
            ))}
          </div>
        </ConsolePanel>

        <ConsolePanel className="p-5">
          <ConsolePanelHeader
            title="Weak Secret Alerts"
            action={health.issues.length > 0 ? <StatusPill tone="danger">{health.issues.length}</StatusPill> : <StatusPill tone="success">0</StatusPill>}
          />
          <div className="mt-4 space-y-2">
            {health.issues.length === 0 ? (
              <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
                No stale login secrets found in the loaded vault summary.
              </div>
            ) : (
              health.issues.slice(0, 3).map((issue) => (
                <div key={`${issue.itemId}-${issue.issue}`} className="grid grid-cols-[1fr_auto] items-center gap-3 border-b border-border/70 py-3 last:border-b-0">
                  <div className="flex min-w-0 items-center gap-2">
                    <KeyRound className="h-4 w-4 text-amber-400" />
                    <span className="truncate text-sm font-medium">{issue.itemName}</span>
                    <span className="truncate text-xs text-muted-foreground">{issue.issue}</span>
                  </div>
                  <StatusPill tone={issue.severity === 'critical' || issue.severity === 'high' ? 'danger' : 'warning'}>{issue.severity}</StatusPill>
                </div>
              ))
            )}
          </div>
        </ConsolePanel>

        <ConsolePanel className="p-5">
          <ConsolePanelHeader
            title="Recent Sensitive Accesses"
            action={(
              <div className="flex items-center gap-2">
                <StatusPill tone={auditStatus?.verified ? 'success' : auditStatus?.entry_count ? 'danger' : 'muted'}>
                  {auditStatus?.verified ? 'Hash Chain Verified' : auditStatus?.entry_count ? 'Hash Chain Failed' : 'No Chain Yet'}
                </StatusPill>
                <Button variant="ghost" size="sm" onClick={onAudit}>View Full Audit Log</Button>
              </div>
            )}
          />
          <ConsoleTable className="mt-4">
            <thead>
              <tr>
                <ConsoleTh>Time</ConsoleTh>
                <ConsoleTh>Member</ConsoleTh>
                <ConsoleTh>Action</ConsoleTh>
                <ConsoleTh>Secret / Resource</ConsoleTh>
                <ConsoleTh>IP / Peer</ConsoleTh>
                <ConsoleTh>Result</ConsoleTh>
              </tr>
            </thead>
            <tbody>
              {auditLoading ? (
                <tr>
                  <ConsoleTd colSpan={6} className="text-muted-foreground">Loading audit activity...</ConsoleTd>
                </tr>
              ) : auditEntries.length === 0 ? (
                <tr>
                  <ConsoleTd colSpan={6} className="text-muted-foreground">No audit entries have been recorded for this vault yet.</ConsoleTd>
                </tr>
              ) : (
                auditEntries.map((entry) => (
                  <tr key={entry.id}>
                    <ConsoleTd className="font-mono text-xs">{new Date(entry.created_at).toLocaleTimeString()}</ConsoleTd>
                    <ConsoleTd>{memberDisplayName(entry.member_id)}</ConsoleTd>
                    <ConsoleTd>{actionLabel(entry.action)}</ConsoleTd>
                    <ConsoleTd className="font-mono text-xs">{entry.item_id || vault.name}</ConsoleTd>
                    <ConsoleTd className="font-mono text-xs">{entry.remote_addr || '-'}</ConsoleTd>
                    <ConsoleTd>
                      <StatusPill tone="success">Success</StatusPill>
                    </ConsoleTd>
                  </tr>
                ))
              )}
            </tbody>
          </ConsoleTable>
        </ConsolePanel>
      </div>

      <ConsolePanel className="p-4">
        <div className="grid gap-3 md:grid-cols-4">
          <div className="flex items-center gap-3">
            <ShieldCheck className={cn('h-5 w-5', twoFactorEnabled ? 'text-primary' : 'text-amber-400')} />
            <div>
              <p className="text-sm font-semibold">Two-factor</p>
              <p className="text-xs text-muted-foreground">{twoFactorEnabled ? 'Enabled' : 'Not enabled'}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <KeyRound className={cn('h-5 w-5', passkeyCount > 0 ? 'text-primary' : 'text-amber-400')} />
            <div>
              <p className="text-sm font-semibold">Passkeys</p>
              <p className="text-xs text-muted-foreground">{passkeyCount} registered</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <AlertTriangle className={cn('h-5 w-5', recoveryCodesUnused > 0 ? 'text-primary' : 'text-amber-400')} />
            <div>
              <p className="text-sm font-semibold">Recovery Codes</p>
              <p className="text-xs text-muted-foreground">{recoveryCodesUnused} unused</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <Network className={cn('h-5 w-5', postureStrong ? 'text-primary' : 'text-amber-400')} />
            <div>
              <p className="text-sm font-semibold">Posture</p>
              <p className="text-xs text-muted-foreground">{postureStrong ? 'Everything secure' : 'Review recommended'}</p>
            </div>
          </div>
        </div>
      </ConsolePanel>
    </div>
  );
}
