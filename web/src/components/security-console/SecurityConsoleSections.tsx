import { useEffect, useState } from 'react';
import type React from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  Download,
  Fingerprint,
  FileKey2,
  KeyRound,
  Lock,
  Network,
  Plus,
  Search,
  Shield,
  ShieldCheck,
  Trash2,
  Upload,
  UserRoundPlus,
  UserRoundX,
  Wand2,
} from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import ItemCard from '@/components/ItemCard';
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
import {
  cancelInvite,
  AuditStatus,
  getCACert,
  getCAInfo,
  getCRL,
  getAuditStatus,
  getMPCMetrics,
  InviteSummary,
  listAuditLogs,
  listInvites,
  listMPCKeys,
  listMPCSigningSessions,
  MPCKey,
  MPCMetrics,
  MPCSigningSession,
} from '@/lib/api';
import { AuditEntry, CAInfo, ItemType, itemName, itemType, itemUpdatedAt, Vault } from '@/types/vault';

const TYPE_FILTERS: { value: ItemType | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'login', label: 'Login' },
  { value: 'note', label: 'Note' },
  { value: 'card', label: 'Card' },
  { value: 'certificate', label: 'Cert' },
  { value: 'custom', label: 'Custom' },
];

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

export function VaultSecretsSection({
  vault,
  onBack,
  onAddItem,
  onShare,
  onAudit,
  onMPC,
  onImport,
  onExport,
  onInitCA,
  onIssueCert,
  onDelete,
}: {
  vault: Vault;
  onBack: () => void;
  onAddItem: () => void;
  onShare: () => void;
  onAudit: () => void;
  onMPC: () => void;
  onImport: () => void;
  onExport: () => void;
  onInitCA: () => void;
  onIssueCert: () => void;
  onDelete: () => void;
}) {
  const [query, setQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ItemType | 'all'>('all');

  const filtered = vault.items.filter((item) => {
    const matchesType = typeFilter === 'all' || itemType(item) === typeFilter;
    const haystack = `${itemName(item)} ${Object.values(item.fields).join(' ')}`.toLowerCase();
    return matchesType && haystack.includes(query.trim().toLowerCase());
  });

  return (
    <div className="space-y-4">
      <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
        <div className="flex min-w-0 items-start gap-3">
          <Button variant="ghost" size="icon" onClick={onBack} title="Back to vaults">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <div className="min-w-0">
            <p className="console-kicker mb-1">Vault</p>
            <h1 className="truncate text-2xl font-semibold">{vault.name}</h1>
            <p className="mt-1 max-w-2xl text-sm text-muted-foreground">{vault.description || 'No description'}</p>
          </div>
        </div>
        <div className="flex flex-wrap gap-2">
          <Button onClick={onAddItem}><Plus className="h-4 w-4" />Add Item</Button>
          <Button variant="outline" onClick={onShare}><UserRoundPlus className="h-4 w-4" />Share</Button>
          <Button variant="outline" onClick={onAudit}><ShieldCheck className="h-4 w-4" />Audit</Button>
          <Button variant="outline" onClick={onMPC}><Network className="h-4 w-4" />MPC</Button>
          <Button variant="outline" onClick={onExport}><Download className="h-4 w-4" />Export</Button>
          <Button variant="outline" onClick={onImport}><Upload className="h-4 w-4" />Import</Button>
          <Button variant="outline" onClick={vault.isCA ? onIssueCert : onInitCA}><FileKey2 className="h-4 w-4" />{vault.isCA ? 'Issue Cert' : 'Init CA'}</Button>
          <Button variant="ghost" size="icon" onClick={onDelete} className="text-destructive hover:text-destructive" title="Delete vault">
            <Trash2 className="h-4 w-4" />
          </Button>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <ConsolePanel className="p-4"><MetricBlock label="Items" value={vault.items.length} /></ConsolePanel>
        <ConsolePanel className="p-4"><MetricBlock label="Members" value={vault.members.filter((member) => member.status !== 'revoked').length} /></ConsolePanel>
        <ConsolePanel className="p-4"><MetricBlock label="Epoch" value={vault.epoch} tone="success" /></ConsolePanel>
        <ConsolePanel className="p-4"><MetricBlock label="CA" value={vault.isCA ? 'Active' : 'Off'} tone={vault.isCA ? 'success' : 'muted'} /></ConsolePanel>
      </div>

      <ConsolePanel className="p-5">
        <div className="mb-4 grid gap-3 lg:grid-cols-[1fr_auto] lg:items-center">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
            <Input
              value={query}
              onChange={(event) => setQuery(event.target.value)}
              placeholder="Filter secrets in this vault..."
              className="border-border bg-muted pl-9"
            />
          </div>
          <div className="flex flex-wrap gap-1.5">
            {TYPE_FILTERS.map((filter) => (
              <Button
                key={filter.value}
                size="sm"
                variant={typeFilter === filter.value ? 'default' : 'ghost'}
                className="h-8 px-3 text-xs"
                onClick={() => setTypeFilter(filter.value)}
              >
                {filter.label}
              </Button>
            ))}
          </div>
        </div>

        {filtered.length === 0 ? (
          <div className="flex min-h-56 flex-col items-center justify-center rounded-lg border border-border bg-muted/20 p-8 text-center">
            <KeyRound className="mb-3 h-10 w-10 text-muted-foreground" />
            <h2 className="mb-1 text-lg font-semibold">No matching secrets</h2>
            <p className="text-sm text-muted-foreground">Adjust the filter or add a new item to this vault.</p>
          </div>
        ) : (
          <div className="grid gap-3 xl:grid-cols-2">
            {filtered.map((item) => (
              <ItemCard key={item.id} item={item} vaultId={vault.id} />
            ))}
          </div>
        )}
      </ConsolePanel>
    </div>
  );
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
  const [invites, setInvites] = useState<InviteSummary[]>([]);
  const [loadingInvites, setLoadingInvites] = useState(false);

  useEffect(() => {
    if (!vault) {
      setInvites([]);
      return;
    }
    setLoadingInvites(true);
    listInvites(vault.id)
      .then(setInvites)
      .catch(() => setInvites([]))
      .finally(() => setLoadingInvites(false));
  }, [vault]);

  if (!vault) return <EmptyConsole title="Access" body="Create a vault before reviewing access." />;
  const revoked = vault.members.filter((member) => member.status === 'revoked');

  const handleCancelInvite = async (token: string) => {
    await cancelInvite(vault.id, token);
    setInvites((current) => current.filter((invite) => invite.token !== token));
  };

  return (
    <div className="grid gap-3 xl:grid-cols-[1fr_1fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader
          title="Access Requests"
          action={<StatusPill tone={invites.length > 0 ? 'warning' : 'success'}>{invites.length} pending</StatusPill>}
        />
        <div className="mt-4 space-y-2">
          {loadingInvites ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              Loading active invites...
            </div>
          ) : invites.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              No pending invites for this vault.
            </div>
          ) : invites.map((invite) => (
            <div key={invite.token} className="flex items-center justify-between gap-3 rounded-lg border border-border bg-muted/25 p-3">
              <div className="min-w-0">
                <p className="truncate text-sm font-semibold">Invite token {invite.token.slice(0, 10)}...</p>
                <p className="text-xs text-muted-foreground">
                  Role: <span className="capitalize">{invite.role}</span> · Expires {new Date(invite.expires_at).toLocaleString()}
                </p>
              </div>
              <Button variant="outline" size="sm" onClick={() => { void handleCancelInvite(invite.token); }}>
                Cancel
              </Button>
            </div>
          ))}
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
  const [keys, setKeys] = useState<MPCKey[]>([]);
  const [sessions, setSessions] = useState<MPCSigningSession[]>([]);
  const [metrics, setMetrics] = useState<MPCMetrics | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!vault) {
      setKeys([]);
      setSessions([]);
      setMetrics(null);
      return;
    }
    setLoading(true);
    Promise.all([
      listMPCKeys(vault.id).catch(() => []),
      listMPCSigningSessions(vault.id).catch(() => []),
      getMPCMetrics(vault.id).catch(() => null),
    ])
      .then(([nextKeys, nextSessions, nextMetrics]) => {
        setKeys(nextKeys);
        setSessions(nextSessions);
        setMetrics(nextMetrics);
      })
      .finally(() => setLoading(false));
  }, [vault]);

  if (!vault) return <EmptyConsole title="MPC" body="Create a vault before configuring MPC signing." />;
  const signers = vault.members.filter((member) => member.status !== 'revoked' && (member.mpc_party_id || member.mpc_signer_status));
  const pendingSessions = sessions.filter((session) => session.status === 'pending').length || metrics?.signing_sessions_by_status?.pending || 0;
  const activeKeys = keys.filter((key) => key.status === 'active');

  return (
    <div className="space-y-3">
    <div className="grid gap-3 xl:grid-cols-[0.8fr_1.2fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="MPC Readiness" action={<StatusPill tone={signers.length >= 2 && activeKeys.length > 0 ? 'success' : 'warning'}>{signers.length} signer{signers.length === 1 ? '' : 's'}</StatusPill>} />
        <div className="mt-5 space-y-4">
          <MetricBlock label="Active Keys" value={loading ? '...' : activeKeys.length} tone={activeKeys.length > 0 ? 'success' : 'warning'} />
          <MetricBlock label="Pending Sessions" value={pendingSessions} tone={pendingSessions > 0 ? 'warning' : 'muted'} />
          <MetricBlock label="Threshold" value={activeKeys[0] ? `${activeKeys[0].threshold}-of-${activeKeys[0].participants.length}` : signers.length >= 2 ? 'Configured signers' : 'Not ready'} tone={activeKeys.length > 0 ? 'success' : signers.length >= 2 ? 'warning' : 'warning'} />
          <Button onClick={onOpenMPC}>
            <Network className="h-4 w-4" />
            Open MPC Controls
          </Button>
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="MPC Keys" action={<StatusPill tone={activeKeys.length > 0 ? 'success' : 'muted'}>{keys.length} key{keys.length === 1 ? '' : 's'}</StatusPill>} />
        <div className="mt-4 space-y-3">
          {loading ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              Loading MPC key status...
            </div>
          ) : keys.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              No MPC keys have been created for this vault yet.
            </div>
          ) : keys.map((key) => (
            <div key={key.key_id} className="rounded-lg border border-border bg-muted/25 p-3">
              <div className="flex items-center justify-between gap-3">
                <div className="min-w-0">
                  <p className="truncate text-sm font-semibold">{key.key_id}</p>
                  <p className="text-xs text-muted-foreground">{key.algorithm} · {key.threshold}-of-{key.participants.length}</p>
                </div>
                <StatusPill tone={key.status === 'active' ? 'success' : key.status === 'disabled' ? 'warning' : 'muted'}>{key.status}</StatusPill>
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {key.participants.map((participant) => (
                  <StatusPill key={`${key.key_id}-${participant.party_id}`} tone={participant.signer_status === 'offline' ? 'danger' : 'muted'}>
                    P{participant.party_id} {participant.member_id}
                  </StatusPill>
                ))}
              </div>
            </div>
          ))}
        </div>
      </ConsolePanel>
    </div>
    <ConsolePanel className="p-5">
      <ConsolePanelHeader title="Signing Sessions" action={<StatusPill tone={pendingSessions > 0 ? 'warning' : 'muted'}>{pendingSessions} pending</StatusPill>} />
      <ConsoleTable className="mt-4">
        <thead>
          <tr>
            <ConsoleTh>Session</ConsoleTh>
            <ConsoleTh>Key</ConsoleTh>
            <ConsoleTh>Type</ConsoleTh>
            <ConsoleTh>Approvals</ConsoleTh>
            <ConsoleTh>Expires</ConsoleTh>
            <ConsoleTh>Status</ConsoleTh>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">Loading signing sessions...</ConsoleTd></tr>
          ) : sessions.length === 0 ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">No MPC signing sessions have been created for this vault.</ConsoleTd></tr>
          ) : sessions.map((session) => (
            <tr key={session.session_id}>
              <ConsoleTd className="font-mono text-xs">{session.session_id}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{session.key_id}</ConsoleTd>
              <ConsoleTd>{session.message_type || 'raw'}</ConsoleTd>
              <ConsoleTd>{session.approvals?.length ?? 0}/{session.participants.length}</ConsoleTd>
              <ConsoleTd>{new Date(session.expires_at).toLocaleString()}</ConsoleTd>
              <ConsoleTd><StatusPill tone={session.status === 'pending' ? 'warning' : session.status === 'completed' ? 'success' : session.status === 'failed' ? 'danger' : 'muted'}>{session.status}</StatusPill></ConsoleTd>
            </tr>
          ))}
        </tbody>
      </ConsoleTable>
    </ConsolePanel>
    </div>
  );
}

export function AuditSection({ vault }: { vault: Vault | null }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    if (!vault) {
      setEntries([]);
      setStatus(null);
      return;
    }
    setLoading(true);
    Promise.all([
      listAuditLogs(vault.id, undefined, { limit: 50, offset: 0 }).catch(() => ({ data: [] as AuditEntry[] })),
      getAuditStatus(vault.id).catch(() => null),
    ])
      .then(([result, nextStatus]) => {
        setEntries(result.data);
        setStatus(nextStatus);
      })
      .finally(() => setLoading(false));
  }, [vault]);

  if (!vault) return <EmptyConsole title="Audit" body="Create a vault before reviewing audit history." />;
  return (
    <div className="space-y-3">
    <div className="grid gap-3 md:grid-cols-3">
      <ConsolePanel className="p-5">
        <MetricBlock label="Hash Chain" value={status?.verified ? 'Verified' : status?.entry_count ? 'Failed' : 'Empty'} tone={status?.verified ? 'success' : status?.entry_count ? 'danger' : 'muted'} />
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <MetricBlock label="Entries" value={status?.entry_count ?? entries.length} />
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <MetricBlock label="Latest Entry" value={status?.latest_entry_at ? new Date(status.latest_entry_at).toLocaleDateString() : '-'} />
      </ConsolePanel>
    </div>
    <ConsolePanel className="p-5">
      <ConsolePanelHeader title="Audit Log" action={<StatusPill tone={status?.verified ? 'success' : entries.length ? 'danger' : 'muted'}>{status?.verified ? 'Verified' : entries.length ? 'Review' : 'Empty'}</StatusPill>} />
      <ConsoleTable className="mt-4">
        <thead>
          <tr>
            <ConsoleTh>Time</ConsoleTh>
            <ConsoleTh>Member</ConsoleTh>
            <ConsoleTh>Action</ConsoleTh>
            <ConsoleTh>Resource</ConsoleTh>
            <ConsoleTh>IP / Peer</ConsoleTh>
            <ConsoleTh>Client</ConsoleTh>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">Loading audit entries...</ConsoleTd></tr>
          ) : entries.length === 0 ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">No audit entries recorded for this vault.</ConsoleTd></tr>
          ) : entries.map((entry) => (
            <tr key={entry.id}>
              <ConsoleTd>{new Date(entry.created_at).toLocaleString()}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{entry.member_id}</ConsoleTd>
              <ConsoleTd>{actionLabel(entry.action)}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{entry.item_id || vault.name}</ConsoleTd>
              <ConsoleTd className="font-mono text-xs">{entry.remote_addr || '-'}</ConsoleTd>
              <ConsoleTd className="max-w-[220px] truncate text-xs text-muted-foreground" title={entry.user_agent || ''}>{entry.user_agent || '-'}</ConsoleTd>
            </tr>
          ))}
        </tbody>
      </ConsoleTable>
    </ConsolePanel>
    </div>
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
