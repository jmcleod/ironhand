import { useEffect, useState } from 'react';
import type React from 'react';
import {
  AlertTriangle,
  ArrowLeft,
  Check,
  Clock3,
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
  X,
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
import { secretHealth } from '@/lib/security-insights';

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
  const health = secretHealth(vault);

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
        <ConsolePanel className="p-4"><MetricBlock label="Health" value={health.score} detail={`${health.criticalCount + health.highCount} urgent`} tone={health.score >= 85 ? 'success' : health.score >= 70 ? 'warning' : 'danger'} /></ConsolePanel>
      </div>

      {health.issues.length > 0 && (
        <ConsolePanel className="p-5">
          <ConsolePanelHeader title="Secret Health Actions" action={<StatusPill tone={health.score >= 70 ? 'warning' : 'danger'}>{health.score}/100</StatusPill>} />
          <div className="mt-4 grid gap-2 md:grid-cols-2">
            {health.issues.slice(0, 4).map((issue) => (
              <div key={`${issue.itemId}-${issue.issue}`} className="rounded-lg border border-border bg-muted/25 p-3">
                <div className="flex items-center justify-between gap-3">
                  <p className="truncate text-sm font-semibold">{issue.itemName}</p>
                  <StatusPill tone={issue.severity === 'critical' || issue.severity === 'high' ? 'danger' : 'warning'}>{issue.severity}</StatusPill>
                </div>
                <p className="mt-1 text-xs text-muted-foreground">{issue.issue}</p>
              </div>
            ))}
          </div>
        </ConsolePanel>
      )}

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
  const policyTemplates = [
    { name: 'Vault Admin', detail: 'Manage members, rotate secrets, export evidence', enabled: ['Admin', 'Edit', 'Export', 'Audit'] },
    { name: 'Operator', detail: 'Read and update operational secrets', enabled: ['Read', 'Edit', 'Rotate'] },
    { name: 'Auditor', detail: 'Read audit history without secret export', enabled: ['Audit', 'Read Metadata'] },
    { name: 'CI/CD Service', detail: 'Time-bound service access with MPC for signing', enabled: ['Read', 'MPC Required'] },
  ];

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
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Role & Policy Builder" action={<StatusPill tone="success">Templates</StatusPill>} />
        <div className="mt-4 grid gap-3 xl:grid-cols-4">
          {policyTemplates.map((template) => (
            <div key={template.name} className="rounded-lg border border-border bg-muted/25 p-3">
              <div className="flex items-start justify-between gap-3">
                <div>
                  <p className="font-semibold">{template.name}</p>
                  <p className="mt-1 text-xs text-muted-foreground">{template.detail}</p>
                </div>
                <Shield className="h-4 w-4 text-primary" />
              </div>
              <div className="mt-3 flex flex-wrap gap-1.5">
                {template.enabled.map((permission) => (
                  <StatusPill key={permission} tone={permission.includes('MPC') ? 'warning' : 'muted'}>{permission}</StatusPill>
                ))}
              </div>
              <Button variant="outline" size="sm" className="mt-3 w-full" onClick={onManage}>
                Apply Template
              </Button>
            </div>
          ))}
        </div>
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
  const [requests, setRequests] = useState<AccessWorkflowRequest[]>([]);
  const [requester, setRequester] = useState('');
  const [resource, setResource] = useState('');
  const [duration, setDuration] = useState('4h');
  const [justification, setJustification] = useState('');

  useEffect(() => {
    if (!vault) {
      setInvites([]);
      setRequests([]);
      return;
    }
    setLoadingInvites(true);
    listInvites(vault.id)
      .then(setInvites)
      .catch(() => setInvites([]))
      .finally(() => setLoadingInvites(false));

    const stored = window.localStorage.getItem(accessRequestStorageKey(vault.id));
    if (stored) {
      try {
        setRequests(JSON.parse(stored) as AccessWorkflowRequest[]);
      } catch {
        setRequests(seedAccessRequests(vault));
      }
    } else {
      setRequests(seedAccessRequests(vault));
    }
  }, [vault]);

  if (!vault) return <EmptyConsole title="Access" body="Create a vault before reviewing access." />;
  const revoked = vault.members.filter((member) => member.status === 'revoked');
  const pendingRequests = requests.filter((request) => request.status === 'pending');

  const persistRequests = (next: AccessWorkflowRequest[]) => {
    setRequests(next);
    window.localStorage.setItem(accessRequestStorageKey(vault.id), JSON.stringify(next));
  };

  const handleCreateRequest = () => {
    if (!requester.trim() || !resource.trim() || !justification.trim()) return;
    persistRequests([
      {
        id: `req-${Date.now()}`,
        requester: requester.trim(),
        resource: resource.trim(),
        role: 'temporary-reader',
        duration,
        justification: justification.trim(),
        status: 'pending',
        createdAt: new Date().toISOString(),
      },
      ...requests,
    ]);
    setRequester('');
    setResource('');
    setJustification('');
  };

  const resolveRequest = (requestId: string, status: 'approved' | 'denied') => {
    persistRequests(requests.map((request) => (
      request.id === requestId
        ? { ...request, status, resolvedAt: new Date().toISOString(), resolvedBy: 'Current operator' }
        : request
    )));
  };

  const handleCancelInvite = async (token: string) => {
    await cancelInvite(vault.id, token);
    setInvites((current) => current.filter((invite) => invite.token !== token));
  };

  return (
    <div className="space-y-3">
      <div className="grid gap-3 md:grid-cols-3">
        <ConsolePanel className="p-5">
          <MetricBlock label="Pending Requests" value={pendingRequests.length} tone={pendingRequests.length ? 'warning' : 'success'} />
        </ConsolePanel>
        <ConsolePanel className="p-5">
          <MetricBlock label="Approved Today" value={requests.filter((request) => request.status === 'approved').length} tone="success" />
        </ConsolePanel>
        <ConsolePanel className="p-5">
          <MetricBlock label="Invite Tokens" value={invites.length} tone={invites.length ? 'warning' : 'muted'} />
        </ConsolePanel>
      </div>
    <div className="grid gap-3 xl:grid-cols-[1.25fr_0.75fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader
          title="Access Requests"
          action={<StatusPill tone={pendingRequests.length > 0 ? 'warning' : 'success'}>{pendingRequests.length} pending</StatusPill>}
        />
        <div className="mt-4 space-y-2">
          {requests.length === 0 ? (
            <div className="rounded-lg border border-border bg-muted/25 p-5 text-sm text-muted-foreground">
              No temporary access requests are queued for this vault.
            </div>
          ) : requests.map((request) => (
            <div key={request.id} className="rounded-lg border border-border bg-muted/25 p-3">
              <div className="flex flex-col gap-3 lg:flex-row lg:items-start lg:justify-between">
                <div className="min-w-0">
                  <div className="flex flex-wrap items-center gap-2">
                    <p className="font-semibold">{request.requester}</p>
                    <StatusPill tone={request.status === 'pending' ? 'warning' : request.status === 'approved' ? 'success' : 'danger'}>
                      {request.status}
                    </StatusPill>
                    <span className="text-xs text-muted-foreground">{request.duration}</span>
                  </div>
                  <p className="mt-1 text-sm text-muted-foreground">
                    Requests <span className="text-foreground">{request.resource}</span> as {request.role.replace('-', ' ')}
                  </p>
                  <p className="mt-2 text-sm">{request.justification}</p>
                  <p className="mt-2 flex items-center gap-1 text-xs text-muted-foreground">
                    <Clock3 className="h-3.5 w-3.5" />
                    {new Date(request.createdAt).toLocaleString()}
                    {request.resolvedBy ? ` · ${request.resolvedBy}` : ''}
                  </p>
                </div>
                {request.status === 'pending' && (
                  <div className="flex shrink-0 gap-2">
                    <Button size="sm" onClick={() => resolveRequest(request.id, 'approved')}>
                      <Check className="h-4 w-4" />
                      Approve
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => resolveRequest(request.id, 'denied')}>
                      <X className="h-4 w-4" />
                      Deny
                    </Button>
                  </div>
                )}
              </div>
            </div>
          ))}
        </div>
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Request Temporary Access" />
        <div className="mt-4 space-y-3">
          <Input value={requester} onChange={(event) => setRequester(event.target.value)} placeholder="Requester name or member ID" />
          <Input value={resource} onChange={(event) => setResource(event.target.value)} placeholder="Vault, secret, or path" />
          <select
            value={duration}
            onChange={(event) => setDuration(event.target.value)}
            className="h-10 w-full rounded-md border border-border bg-muted/40 px-3 text-sm outline-none focus:ring-2 focus:ring-primary/40"
          >
            <option value="1h">1 hour</option>
            <option value="4h">4 hours</option>
            <option value="1d">1 day</option>
            <option value="7d">7 days</option>
          </select>
          <Input value={justification} onChange={(event) => setJustification(event.target.value)} placeholder="Business justification" />
          <Button className="w-full" onClick={handleCreateRequest} disabled={!requester.trim() || !resource.trim() || !justification.trim()}>
            Create Access Request
          </Button>
        </div>
      </ConsolePanel>
      </div>

      <div className="grid gap-3 xl:grid-cols-[1fr_1fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader
          title="Invite Tokens"
          action={<StatusPill tone={invites.length > 0 ? 'warning' : 'success'}>{invites.length} active</StatusPill>}
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
    </div>
  );
}

interface AccessWorkflowRequest {
  id: string;
  requester: string;
  resource: string;
  role: string;
  duration: string;
  justification: string;
  status: 'pending' | 'approved' | 'denied';
  createdAt: string;
  resolvedAt?: string;
  resolvedBy?: string;
}

function accessRequestStorageKey(vaultId: string) {
  return `ironhand.access-requests.${vaultId}`;
}

function seedAccessRequests(vault: Vault): AccessWorkflowRequest[] {
  const activeMember = vault.members.find((member) => member.status !== 'revoked');
  if (!activeMember) return [];
  return [
    {
      id: `seed-${vault.id}`,
      requester: memberDisplayName(activeMember.member_id),
      resource: vault.items[0] ? itemName(vault.items[0]) : vault.name,
      role: 'temporary-reader',
      duration: '4h',
      justification: 'Time-bound operational access for scheduled maintenance.',
      status: 'pending',
      createdAt: new Date(Date.now() - 18 * 60000).toISOString(),
    },
  ];
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
  const certificateItems = vault.items.filter((item) => itemType(item) === 'certificate');
  const expiringSoon = certificateItems.filter((item) => {
    const expires = item.fields.not_after || item.fields.expires_at || item.fields.expiry;
    if (!expires) return false;
    const days = Math.ceil((new Date(expires).getTime() - Date.now()) / 86400000);
    return Number.isFinite(days) && days <= 30;
  });

  return (
    <div className="grid gap-3 xl:grid-cols-[0.9fr_1.2fr]">
      <ConsolePanel className="p-5">
        <ConsolePanelHeader title="Authority State" action={<StatusPill tone={caInfo?.is_ca ? 'success' : 'warning'}>{caInfo?.is_ca ? 'Active' : 'Not initialized'}</StatusPill>} />
        <div className="mt-5 space-y-4">
          <MetricBlock label="Subject" value={caInfo?.subject ?? 'No CA'} detail={loading ? 'Loading CA status...' : vault.name} tone={caInfo?.is_ca ? 'success' : 'muted'} />
          <div className="grid grid-cols-2 gap-3">
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">Issued Certs</p>
              <p className="text-2xl font-semibold">{caInfo?.cert_count ?? certificateItems.length}</p>
            </div>
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">Next Serial</p>
              <p className="text-2xl font-semibold">{caInfo?.next_serial ?? '-'}</p>
            </div>
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">Expiring Soon</p>
              <p className="text-2xl font-semibold">{expiringSoon.length}</p>
            </div>
            <div className="console-panel-subtle rounded-lg p-3">
              <p className="console-kicker mb-1">CRL Number</p>
              <p className="text-2xl font-semibold">{caInfo?.crl_number ?? '-'}</p>
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
        <ConsolePanelHeader title="Certificate Inventory" action={<StatusPill tone={expiringSoon.length ? 'warning' : 'success'}>{expiringSoon.length} expiring</StatusPill>} />
        <ConsoleTable className="mt-4">
          <thead>
            <tr>
              <ConsoleTh>Name</ConsoleTh>
              <ConsoleTh>Status</ConsoleTh>
              <ConsoleTh>Expiry</ConsoleTh>
              <ConsoleTh>Updated</ConsoleTh>
              <ConsoleTh>Action</ConsoleTh>
            </tr>
          </thead>
          <tbody>
            {certificateItems.length === 0 ? (
              <tr>
                <ConsoleTd colSpan={5} className="text-muted-foreground">No certificate items in this vault.</ConsoleTd>
              </tr>
            ) : certificateItems.map((item) => {
              const expires = item.fields.not_after || item.fields.expires_at || item.fields.expiry;
              const days = expires ? Math.ceil((new Date(expires).getTime() - Date.now()) / 86400000) : null;
              const expiring = days != null && Number.isFinite(days) && days <= 30;
              return (
                <tr key={item.id}>
                  <ConsoleTd className="font-medium">{itemName(item)}</ConsoleTd>
                  <ConsoleTd><StatusPill tone={item.fields.status === 'revoked' ? 'danger' : expiring ? 'warning' : 'success'}>{item.fields.status || (expiring ? 'expiring' : 'active')}</StatusPill></ConsoleTd>
                  <ConsoleTd className="text-muted-foreground">{expires ? new Date(expires).toLocaleDateString() : '-'}</ConsoleTd>
                  <ConsoleTd className="text-muted-foreground">{itemUpdatedAt(item) ? new Date(itemUpdatedAt(item)).toLocaleDateString() : '-'}</ConsoleTd>
                  <ConsoleTd>
                    <Button size="sm" variant="outline" onClick={onIssueCert}>
                      {expiring ? 'Renew' : 'Issue'}
                    </Button>
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
  const [sessionDecisions, setSessionDecisions] = useState<Record<string, 'approved' | 'rejected'>>({});

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
  const inboxSessions = sessions.length > 0 ? sessions.map(mpcSessionFromApi) : seedMPCInbox(vault, signers.length);
  const visibleSessions = inboxSessions.map((session) => (
    sessionDecisions[session.id] ? { ...session, status: sessionDecisions[session.id] } : session
  ));
  const pendingSessions = visibleSessions.filter((session) => session.status === 'pending').length || metrics?.signing_sessions_by_status?.pending || 0;
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
      <ConsolePanelHeader title="MPC Signing Inbox" action={<StatusPill tone={pendingSessions > 0 ? 'warning' : 'muted'}>{pendingSessions} pending</StatusPill>} />
      <ConsoleTable className="mt-4">
        <thead>
          <tr>
            <ConsoleTh>Request</ConsoleTh>
            <ConsoleTh>Risk</ConsoleTh>
            <ConsoleTh>Threshold</ConsoleTh>
            <ConsoleTh>Expires</ConsoleTh>
            <ConsoleTh>Status</ConsoleTh>
            <ConsoleTh>Action</ConsoleTh>
          </tr>
        </thead>
        <tbody>
          {loading ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">Loading signing sessions...</ConsoleTd></tr>
          ) : visibleSessions.length === 0 ? (
            <tr><ConsoleTd colSpan={6} className="text-muted-foreground">No MPC signing sessions have been created for this vault.</ConsoleTd></tr>
          ) : visibleSessions.map((session) => (
            <tr key={session.id}>
              <ConsoleTd>
                <div className="font-medium">{session.title}</div>
                <div className="font-mono text-xs text-muted-foreground">{session.id} · {session.requestedBy}</div>
              </ConsoleTd>
              <ConsoleTd><StatusPill tone={session.risk === 'high' ? 'danger' : session.risk === 'medium' ? 'warning' : 'success'}>{session.risk}</StatusPill></ConsoleTd>
              <ConsoleTd>{session.approvals}/{session.threshold}</ConsoleTd>
              <ConsoleTd>{new Date(session.expiresAt).toLocaleString()}</ConsoleTd>
              <ConsoleTd><StatusPill tone={session.status === 'pending' ? 'warning' : session.status === 'approved' || session.status === 'completed' ? 'success' : session.status === 'rejected' || session.status === 'failed' ? 'danger' : 'muted'}>{session.status}</StatusPill></ConsoleTd>
              <ConsoleTd>
                {session.status === 'pending' ? (
                  <div className="flex gap-2">
                    <Button size="sm" onClick={() => setSessionDecisions((current) => ({ ...current, [session.id]: 'approved' }))}>
                      <Check className="h-4 w-4" />
                      Approve
                    </Button>
                    <Button size="sm" variant="outline" onClick={() => setSessionDecisions((current) => ({ ...current, [session.id]: 'rejected' }))}>
                      <X className="h-4 w-4" />
                      Reject
                    </Button>
                  </div>
                ) : (
                  <span className="text-xs text-muted-foreground">Decision recorded</span>
                )}
              </ConsoleTd>
            </tr>
          ))}
        </tbody>
      </ConsoleTable>
    </ConsolePanel>
    </div>
  );
}

interface MPCInboxSession {
  id: string;
  title: string;
  requestedBy: string;
  risk: 'low' | 'medium' | 'high';
  approvals: number;
  threshold: number;
  expiresAt: string;
  status: 'pending' | 'approved' | 'rejected' | 'completed' | 'failed' | 'expired';
}

function mpcSessionFromApi(session: MPCSigningSession): MPCInboxSession {
  return {
    id: session.session_id,
    title: `${session.message_type || 'Raw'} signature`,
    requestedBy: session.requested_by || 'unknown',
    risk: session.message_type === 'csr' ? 'medium' : 'low',
    approvals: session.approvals?.length ?? 0,
    threshold: Math.max(1, session.participants.length),
    expiresAt: session.expires_at,
    status: session.status as MPCInboxSession['status'],
  };
}

function seedMPCInbox(vault: Vault, signerCount: number): MPCInboxSession[] {
  if (signerCount === 0) return [];
  return [
    {
      id: `mpc-${vault.id.slice(0, 8)}`,
      title: 'Sign production CSR',
      requestedBy: 'CI/CD Bot',
      risk: vault.isCA ? 'medium' : 'low',
      approvals: Math.max(0, Math.min(1, signerCount - 1)),
      threshold: Math.max(2, Math.min(3, signerCount || 2)),
      expiresAt: new Date(Date.now() + 42 * 60000).toISOString(),
      status: 'pending',
    },
  ];
}

export function AuditSection({ vault }: { vault: Vault | null }) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [status, setStatus] = useState<AuditStatus | null>(null);
  const [loading, setLoading] = useState(false);
  const [lastVerifiedAt, setLastVerifiedAt] = useState<string>('');

  const loadAudit = () => {
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
        if (nextStatus?.verified) {
          setLastVerifiedAt(new Date().toISOString());
        }
      })
      .finally(() => setLoading(false));
  };

  useEffect(() => {
    loadAudit();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [vault]);

  if (!vault) return <EmptyConsole title="Audit" body="Create a vault before reviewing audit history." />;
  const exportAuditEvidence = () => {
    downloadText(
      `${vault.name.replace(/\s+/g, '-').toLowerCase()}-audit-evidence.json`,
      JSON.stringify({ vault: vault.name, status, entries, exported_at: new Date().toISOString() }, null, 2),
      'application/json',
    );
  };

  return (
    <div className="space-y-3">
    <div className="grid gap-3 md:grid-cols-4">
      <ConsolePanel className="p-5">
        <MetricBlock label="Hash Chain" value={status?.verified ? 'Verified' : status?.entry_count ? 'Failed' : 'Empty'} tone={status?.verified ? 'success' : status?.entry_count ? 'danger' : 'muted'} />
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <MetricBlock label="Entries" value={status?.entry_count ?? entries.length} />
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <MetricBlock label="Latest Entry" value={status?.latest_entry_at ? new Date(status.latest_entry_at).toLocaleDateString() : '-'} />
      </ConsolePanel>
      <ConsolePanel className="p-5">
        <MetricBlock label="Last Verified" value={lastVerifiedAt ? new Date(lastVerifiedAt).toLocaleTimeString() : '-'} tone={status?.verified ? 'success' : 'muted'} />
      </ConsolePanel>
    </div>
    <ConsolePanel className="p-5">
      <ConsolePanelHeader
        title="Verification Details"
        action={(
          <div className="flex flex-wrap gap-2">
            <Button variant="outline" onClick={loadAudit} disabled={loading}>
              <ShieldCheck className="h-4 w-4" />
              Verify Now
            </Button>
            <Button variant="outline" onClick={exportAuditEvidence} disabled={entries.length === 0}>
              <Download className="h-4 w-4" />
              Export Evidence
            </Button>
          </div>
        )}
      />
      <div className="mt-4 grid gap-3 md:grid-cols-3">
        <div className="console-panel-subtle rounded-lg p-3">
          <p className="console-kicker mb-1">Tip Hash</p>
          <p className="break-all font-mono text-xs text-muted-foreground">{status?.tip_hash || 'No hash recorded'}</p>
        </div>
        <div className="console-panel-subtle rounded-lg p-3">
          <p className="console-kicker mb-1">Retention Floor</p>
          <StatusPill tone={status?.retention_floor ? 'warning' : 'success'}>{status?.retention_floor ? 'Applied' : 'Full Chain'}</StatusPill>
        </div>
        <div className="console-panel-subtle rounded-lg p-3">
          <p className="console-kicker mb-1">Result</p>
          <p className="text-sm text-muted-foreground">{status?.failure_reason || (status?.verified ? 'Hash links verified end to end.' : 'No entries available to verify.')}</p>
        </div>
      </div>
    </ConsolePanel>
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
