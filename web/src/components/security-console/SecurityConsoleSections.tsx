import { useEffect, useState } from 'react';
import type React from 'react';
import {
  AlertTriangle,
  Check,
  Download,
  Fingerprint,
  FileKey2,
  KeyRound,
  Lock,
  Network,
  Shield,
  ShieldCheck,
  Upload,
  UserRoundPlus,
  UserRoundX,
  Wand2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import ThemeSwitcher from '@/components/ThemeSwitcher';
import {
  ConsolePanel,
  ConsolePanelHeader,
  ConsoleTable,
  ConsoleTd,
  ConsoleTh,
  MetricBlock,
  StatusPill,
} from '@/components/security-console/ConsolePrimitives';
import { getCACert, getCAInfo, getCRL, listAuditLogs } from '@/lib/api';
import { AuditEntry, CAInfo, itemName, itemType, itemUpdatedAt, Vault } from '@/types/vault';

function memberDisplayName(memberID: string) {
  return memberID.replace(/[_-]/g, ' ').replace(/\b\w/g, (char) => char.toUpperCase());
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
      return 'Certificate Issued';
    case 'cert_revoked':
      return 'Certificate Revoked';
    case 'cert_renewed':
      return 'Certificate Renewed';
    case 'crl_generated':
      return 'CRL Generated';
    case 'csr_signed':
      return 'CSR Signed';
    case 'private_key_accessed':
      return 'Private Key Accessed';
  }
}

function downloadText(filename: string, content: string, type = 'application/x-pem-file') {
  const blob = new Blob([content], { type });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement('a');
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

export function MembersSection({
  vault,
  onInvite,
  onManage,
}: {
  vault: Vault | null;
  onInvite: () => void;
  onManage: () => void;
}) {
  if (!vault) return <EmptyConsole title="Members" body="Create a vault before managing members." />;
  const active = vault.members.filter((member) => member.status !== 'revoked');
  const revoked = vault.members.filter((member) => member.status === 'revoked');

  return (
    <div className="space-y-3">
      <div className="grid gap-3 md:grid-cols-3">
        <ConsolePanel className="p-5">
          <MetricBlock label="Active Members" value={active.length} tone="success" />
        </ConsolePanel>
        <ConsolePanel className="p-5">
          <MetricBlock label="Revoked Members" value={revoked.length} tone={revoked.length > 0 ? 'danger' : 'success'} />
        </ConsolePanel>
        <ConsolePanel className="p-5">
          <MetricBlock label="MPC Signers" value={active.filter((member) => member.mpc_party_id || member.mpc_signer_status).length} />
        </ConsolePanel>
      </div>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader
          title="Member Role Matrix"
          action={(
            <div className="flex gap-2">
              <Button variant="outline" onClick={onInvite}>
                <UserRoundPlus className="h-4 w-4" />
                Invite
              </Button>
              <Button variant="outline" onClick={onManage}>Manage Roles</Button>
            </div>
          )}
        />
        <ConsoleTable className="mt-4">
          <thead>
            <tr>
              <ConsoleTh>Member</ConsoleTh>
              <ConsoleTh>Role</ConsoleTh>
              <ConsoleTh>Admin</ConsoleTh>
              <ConsoleTh>Editor</ConsoleTh>
              <ConsoleTh>Viewer</ConsoleTh>
              <ConsoleTh>MPC Signer</ConsoleTh>
              <ConsoleTh>Status</ConsoleTh>
            </tr>
          </thead>
          <tbody>
            {vault.members.map((member) => {
              const owner = member.role === 'owner';
              const writer = owner || member.role === 'writer';
              const reader = writer || member.role === 'reader';
              return (
                <tr key={member.member_id}>
                  <ConsoleTd className="font-medium">{memberDisplayName(member.member_id)}</ConsoleTd>
                  <ConsoleTd className="capitalize">{member.role}</ConsoleTd>
                  {[owner, writer, reader, !!member.mpc_party_id].map((enabled, index) => (
                    <ConsoleTd key={index} className={enabled ? 'text-primary' : 'text-muted-foreground'}>
                      {enabled ? <Check className="h-4 w-4" /> : '-'}
                    </ConsoleTd>
                  ))}
                  <ConsoleTd>
                    <StatusPill tone={member.status === 'revoked' ? 'danger' : 'success'}>{member.status}</StatusPill>
                  </ConsoleTd>
                </tr>
              );
            })}
          </tbody>
        </ConsoleTable>
      </ConsolePanel>
    </div>
  );
}

export function AccessSection({
  vault,
  onInvite,
  onManage,
}: {
  vault: Vault | null;
  onInvite: () => void;
  onManage: () => void;
}) {
  if (!vault) return <EmptyConsole title="Access" body="Create a vault before reviewing access." />;
  const revoked = vault.members.filter((member) => member.status === 'revoked');
  return (
    <div className="grid gap-3 xl:grid-cols-[1fr_1fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader
          title="Access Requests"
          action={<StatusPill tone="muted">Invite-backed</StatusPill>}
        />
        <div className="mt-4 rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
          Pending access requests are not exposed as a standalone endpoint yet. Current invite creation and member management are available through Share.
        </div>
        <div className="mt-4 flex gap-2">
          <Button onClick={onInvite}>
            <UserRoundPlus className="h-4 w-4" />
            Create Invite
          </Button>
          <Button variant="outline" onClick={onManage}>Open Member Controls</Button>
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Revocation Watchlist" action={<StatusPill tone={revoked.length ? 'danger' : 'success'}>{revoked.length}</StatusPill>} />
        <div className="mt-4 space-y-2">
          {revoked.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              No revoked members in this vault.
            </div>
          ) : revoked.map((member) => (
            <div key={member.member_id} className="flex items-center justify-between rounded-lg border border-border bg-muted/25 p-3">
              <span className="flex items-center gap-2 text-sm font-medium">
                <UserRoundX className="h-4 w-4 text-red-400" />
                {memberDisplayName(member.member_id)}
              </span>
              <StatusPill tone="danger">Revoked</StatusPill>
            </div>
          ))}
        </div>
      </ConsolePanel>
    </div>
  );
}

export function CertificateAuthoritySection({
  vault,
  onInitCA,
  onIssueCert,
}: {
  vault: Vault | null;
  onInitCA: () => void;
  onIssueCert: () => void;
}) {
  const [caInfo, setCAInfo] = useState<CAInfo | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!vault) {
      setCAInfo(null);
      return;
    }
    setLoading(true);
    getCAInfo(vault.id)
      .then(setCAInfo)
      .catch(() => setCAInfo(null))
      .finally(() => setLoading(false));
  }, [vault]);

  if (!vault) return <EmptyConsole title="Certificate Authority" body="Create a vault before configuring certificate authority workflows." />;

  return (
    <div className="grid gap-3 xl:grid-cols-[0.9fr_1.2fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Authority State" action={<StatusPill tone={caInfo?.is_ca ? 'success' : 'warning'}>{caInfo?.is_ca ? 'Active' : 'Not initialized'}</StatusPill>} />
        <div className="mt-5 space-y-4">
          <MetricBlock label="Subject" value={caInfo?.subject ?? 'No CA'} detail={loading ? 'Loading CA status...' : vault.name} tone={caInfo?.is_ca ? 'success' : 'muted'} />
          <div className="grid grid-cols-2 gap-3">
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">Issued Certs</p>
              <p className="text-2xl font-semibold">{caInfo?.cert_count ?? vault.items.filter((item) => itemType(item) === 'certificate').length}</p>
            </div>
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">Next Serial</p>
              <p className="text-2xl font-semibold">{caInfo?.next_serial ?? '-'}</p>
            </div>
          </div>
          <div className="flex flex-wrap gap-2">
            <Button onClick={caInfo?.is_ca ? onIssueCert : onInitCA}>
              <FileKey2 className="h-4 w-4" />
              {caInfo?.is_ca ? 'Issue Certificate' : 'Initialize CA'}
            </Button>
            <Button
              variant="outline"
              disabled={!caInfo?.is_ca}
              onClick={async () => vault && downloadText('ca-cert.pem', await getCACert(vault.id))}
            >
              <Download className="h-4 w-4" />
              CA Cert
            </Button>
            <Button
              variant="outline"
              disabled={!caInfo?.is_ca}
              onClick={async () => vault && downloadText('crl.pem', await getCRL(vault.id))}
            >
              <Download className="h-4 w-4" />
              CRL
            </Button>
          </div>
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Certificate Inventory" />
        <ConsoleTable className="mt-4">
          <thead>
            <tr>
              <ConsoleTh>Name</ConsoleTh>
              <ConsoleTh>Status</ConsoleTh>
              <ConsoleTh>Updated</ConsoleTh>
            </tr>
          </thead>
          <tbody>
            {vault.items.filter((item) => itemType(item) === 'certificate').length === 0 ? (
              <tr>
                <ConsoleTd colSpan={3} className="text-muted-foreground">No certificate items in this vault.</ConsoleTd>
              </tr>
            ) : vault.items.filter((item) => itemType(item) === 'certificate').map((item) => (
              <tr key={item.id}>
                <ConsoleTd className="font-medium">{itemName(item)}</ConsoleTd>
                <ConsoleTd><StatusPill tone={item.fields.status === 'revoked' ? 'danger' : 'success'}>{item.fields.status || 'active'}</StatusPill></ConsoleTd>
                <ConsoleTd className="text-muted-foreground">{itemUpdatedAt(item) ? new Date(itemUpdatedAt(item)).toLocaleDateString() : '-'}</ConsoleTd>
              </tr>
            ))}
          </tbody>
        </ConsoleTable>
      </ConsolePanel>
    </div>
  );
}

export function MPCSection({
  vault,
  onOpenMPC,
}: {
  vault: Vault | null;
  onOpenMPC: () => void;
}) {
  if (!vault) return <EmptyConsole title="MPC" body="Create a vault before configuring MPC signing." />;
  const signers = vault.members.filter((member) => member.status !== 'revoked' && (member.mpc_party_id || member.mpc_signer_status));
  return (
    <div className="grid gap-3 xl:grid-cols-[0.8fr_1.2fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="MPC Readiness" action={<StatusPill tone={signers.length >= 2 ? 'success' : 'warning'}>{signers.length} signer{signers.length === 1 ? '' : 's'}</StatusPill>} />
        <div className="mt-5 space-y-4">
          <MetricBlock label="Threshold" value={signers.length >= 3 ? '2-of-3' : signers.length >= 2 ? '2-of-2' : 'Not ready'} tone={signers.length >= 2 ? 'success' : 'warning'} />
          <Button onClick={onOpenMPC}>
            <Network className="h-4 w-4" />
            Open MPC Controls
          </Button>
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Signing Queue" action={<StatusPill tone="muted">Signer-backed</StatusPill>} />
        <div className="mt-4 space-y-2">
          {signers.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              No MPC signers are configured yet. Add signer metadata through MPC controls.
            </div>
          ) : signers.map((member) => (
            <div key={member.member_id} className="flex items-center justify-between rounded-lg border border-border bg-muted/25 p-3">
              <div>
                <p className="text-sm font-semibold">{memberDisplayName(member.member_id)}</p>
                <p className="text-xs text-muted-foreground">{member.mpc_signer_url ?? 'Signer URL not set'}</p>
              </div>
              <StatusPill tone={member.mpc_signer_status === 'offline' ? 'danger' : 'success'}>{member.mpc_signer_status ?? 'configured'}</StatusPill>
            </div>
          ))}
        </div>
      </ConsolePanel>
    </div>
  );
}

export function AuditSection({ vault }: { vault: Vault | null }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!vault) {
      setEntries([]);
      return;
    }
    setLoading(true);
    listAuditLogs(vault.id, undefined, { limit: 50, offset: 0 })
      .then((result) => setEntries(result.data))
      .catch(() => setEntries([]))
      .finally(() => setLoading(false));
  }, [vault]);

  if (!vault) return <EmptyConsole title="Audit" body="Create a vault before reviewing audit history." />;
  return (
    <ConsolePanel className="p-5">
      <ConsolePanelHeader title="Audit Log" action={<StatusPill tone={entries.length ? 'success' : 'muted'}>{entries.length} loaded</StatusPill>} />
      <ConsoleTable className="mt-4">
        <thead>
          <tr>
            <ConsoleTh>Time</ConsoleTh>
            <ConsoleTh>Member</ConsoleTh>
            <ConsoleTh>Action</ConsoleTh>
            <ConsoleTh>Resource</ConsoleTh>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr><ConsoleTd colSpan={4} className="text-muted-foreground">Loading audit entries...</ConsoleTd></tr>
          ) : entries.length === 0 ? (
            <tr><ConsoleTd colSpan={4} className="text-muted-foreground">No audit entries recorded for this vault.</ConsoleTd></tr>
          ) : entries.map((entry) => (
            <tr key={entry.id}>
              <ConsoleTd>{new Date(entry.created_at).toLocaleString()}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{entry.member_id}</ConsoleTd>
              <ConsoleTd>{actionLabel(entry.action)}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{entry.item_id || vault.name}</ConsoleTd>
            </tr>
          ))}
        </tbody>
      </ConsoleTable>
    </ConsolePanel>
  );
}

export function SettingsSection({
  twoFactorEnabled,
  passkeyCount,
  recoveryCodesUnused,
  onTwoFactor,
  onPasskeys,
  onGenerator,
  onLock,
}: {
  twoFactorEnabled: boolean;
  passkeyCount: number;
  recoveryCodesUnused: number;
  onTwoFactor: () => void;
  onPasskeys: () => void;
  onGenerator: () => void;
  onLock: () => void;
}) {
  return (
    <div className="grid gap-3 xl:grid-cols-[1fr_1fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Account Security" />
        <div className="mt-4 space-y-3">
          <SettingRow icon={<ShieldCheck className="h-5 w-5" />} label="Two-factor authentication" value={twoFactorEnabled ? 'Enabled' : 'Not enabled'} tone={twoFactorEnabled ? 'success' : 'warning'} action="Manage" onClick={onTwoFactor} />
          <SettingRow icon={<Fingerprint className="h-5 w-5" />} label="Passkeys" value={`${passkeyCount} registered`} tone={passkeyCount > 0 ? 'success' : 'warning'} action="Manage" onClick={onPasskeys} />
          <SettingRow icon={<AlertTriangle className="h-5 w-5" />} label="Recovery codes" value={`${recoveryCodesUnused} unused`} tone={recoveryCodesUnused > 0 ? 'success' : 'warning'} action="Open" onClick={onPasskeys} />
          <SettingRow icon={<Lock className="h-5 w-5" />} label="Session" value="Unlocked" tone="success" action="Lock" onClick={onLock} />
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Tools" />
        <div className="mt-4 grid gap-3 sm:grid-cols-2">
          <Button variant="outline" onClick={onGenerator}><Wand2 className="h-4 w-4" />Password Generator</Button>
          <ThemeSwitcher />
          <Button variant="outline" disabled><Upload className="h-4 w-4" />Import Defaults</Button>
          <Button variant="outline" disabled><Download className="h-4 w-4" />Export Settings</Button>
        </div>
      </ConsolePanel>
    </div>
  );
}

function SettingRow({
  icon,
  label,
  value,
  tone,
  action,
  onClick,
}: {
  icon: React.ReactNode;
  label: string;
  value: string;
  tone: 'success' | 'warning' | 'danger' | 'muted';
  action: string;
  onClick: () => void;
}) {
  return (
    <div className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/25 p-3">
      <div className="flex min-w-0 items-center gap-3">
        <span className="text-primary">{icon}</span>
        <div className="min-w-0">
          <p className="truncate text-sm font-semibold">{label}</p>
          <p className="text-xs text-muted-foreground">{value}</p>
        </div>
      </div>
      <div className="flex items-center gap-2">
        <StatusPill tone={tone}>{value}</StatusPill>
        <Button variant="outline" size="sm" onClick={onClick}>{action}</Button>
      </div>
    </div>
  );
}

function EmptyConsole({ title, body }: { title: string; body: string }) {
  return (
    <ConsolePanel className="flex min-h-[420px] flex-col items-center justify-center p-8 text-center">
      <Shield className="mb-4 h-12 w-12 text-muted-foreground" />
      <h1 className="mb-2 text-2xl font-semibold">{title}</h1>
      <p className="max-w-md text-sm text-muted-foreground">{body}</p>
    </ConsolePanel>
  );
}
