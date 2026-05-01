import { AuditEntry, itemName, itemType, itemUpdatedAt, userFields, Vault, VaultItem } from '@/types/vault';

export interface SecretHealthIssue {
  itemId: string;
  itemName: string;
  issue: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

export interface SecretHealthSummary {
  score: number;
  totalSecrets: number;
  criticalCount: number;
  highCount: number;
  mediumCount: number;
  issues: SecretHealthIssue[];
}

export interface RiskAlert {
  id: string;
  title: string;
  detail: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
}

const SEVERITY_WEIGHT: Record<SecretHealthIssue['severity'], number> = {
  critical: 28,
  high: 18,
  medium: 10,
  low: 4,
};

export function secretHealth(vault: Vault | null): SecretHealthSummary {
  if (!vault) {
    return { score: 0, totalSecrets: 0, criticalCount: 0, highCount: 0, mediumCount: 0, issues: [] };
  }

  const issues = vault.items.flatMap((item) => healthIssuesForItem(item));
  const penalty = issues.reduce((sum, issue) => sum + SEVERITY_WEIGHT[issue.severity], 0);
  const score = vault.items.length === 0 ? 100 : Math.max(0, 100 - Math.round(penalty / Math.max(1, vault.items.length)));

  return {
    score,
    totalSecrets: vault.items.length,
    criticalCount: issues.filter((issue) => issue.severity === 'critical').length,
    highCount: issues.filter((issue) => issue.severity === 'high').length,
    mediumCount: issues.filter((issue) => issue.severity === 'medium').length,
    issues: issues.slice(0, 8),
  };
}

export function riskAlerts(vault: Vault | null, auditEntries: AuditEntry[] = [], auditVerified = true): RiskAlert[] {
  if (!vault) return [];
  const health = secretHealth(vault);
  const alerts: RiskAlert[] = [];
  const revokedMembers = vault.members.filter((member) => member.status === 'revoked');
  const recentExports = auditEntries.filter((entry) => entry.action === 'vault_exported');
  const blockedAudit = auditEntries.filter((entry) => entry.action === 'private_key_accessed');

  if (!auditVerified && auditEntries.length > 0) {
    alerts.push({
      id: 'audit-chain',
      title: 'Audit chain needs verification',
      detail: 'The latest audit status is not verified. Review chain integrity before exporting evidence.',
      severity: 'critical',
    });
  }

  if (health.criticalCount > 0 || health.highCount > 0) {
    alerts.push({
      id: 'secret-health',
      title: 'Secret hygiene risk detected',
      detail: `${health.criticalCount + health.highCount} high-priority secret issue${health.criticalCount + health.highCount === 1 ? '' : 's'} found.`,
      severity: health.criticalCount > 0 ? 'critical' : 'high',
    });
  }

  if (revokedMembers.length > 0) {
    alerts.push({
      id: 'revoked-members',
      title: 'Revoked member remains in access history',
      detail: `${revokedMembers.length} revoked member${revokedMembers.length === 1 ? '' : 's'} should be monitored for attempted access.`,
      severity: 'medium',
    });
  }

  if (recentExports.length > 0) {
    alerts.push({
      id: 'recent-export',
      title: 'Vault export recorded',
      detail: 'A vault export appears in recent audit history. Confirm it was expected and approved.',
      severity: 'high',
    });
  }

  if (blockedAudit.length > 0) {
    alerts.push({
      id: 'private-key-access',
      title: 'Private key access observed',
      detail: 'Private key material was accessed recently. Review requester, peer address, and purpose.',
      severity: 'critical',
    });
  }

  for (const cert of vault.items.filter((item) => itemType(item) === 'certificate')) {
    const notAfter = cert.fields.not_after || cert.fields.expires_at || cert.fields.expiry;
    const expiresAt = notAfter ? new Date(notAfter).getTime() : Number.NaN;
    if (Number.isFinite(expiresAt)) {
      const days = Math.ceil((expiresAt - Date.now()) / 86400000);
      if (days <= 14) {
        alerts.push({
          id: `cert-${cert.id}`,
          title: 'Certificate expires soon',
          detail: `${itemName(cert)} expires in ${Math.max(0, days)} day${days === 1 ? '' : 's'}.`,
          severity: days <= 3 ? 'high' : 'medium',
        });
      }
    }
  }

  return alerts.sort((a, b) => alertRank(a.severity) - alertRank(b.severity)).slice(0, 6);
}

function alertRank(severity: RiskAlert['severity']) {
  return { critical: 0, high: 1, medium: 2, low: 3 }[severity];
}

function healthIssuesForItem(item: VaultItem): SecretHealthIssue[] {
  const fields = userFields(item);
  const issues: SecretHealthIssue[] = [];
  const name = itemName(item);
  const type = itemType(item);
  const password = fields.password || fields.secret || fields.token || fields.api_key;
  const updatedAt = itemUpdatedAt(item);

  if ((type === 'login' || type === 'custom') && password && password.length < 14) {
    issues.push({ itemId: item.id, itemName: name, issue: 'Weak credential length', severity: 'critical' });
  }

  if ((type === 'login' || type === 'custom') && !password) {
    issues.push({ itemId: item.id, itemName: name, issue: 'No secret field detected', severity: 'medium' });
  }

  if (!fields.owner && !fields.team && !fields.service) {
    issues.push({ itemId: item.id, itemName: name, issue: 'Missing owner metadata', severity: 'medium' });
  }

  if (!updatedAt) {
    issues.push({ itemId: item.id, itemName: name, issue: 'No rotation timestamp', severity: 'high' });
  } else {
    const ageDays = Math.round((Date.now() - new Date(updatedAt).getTime()) / 86400000);
    if (ageDays >= 90) {
      issues.push({ itemId: item.id, itemName: name, issue: `Rotation overdue by ${ageDays}d`, severity: 'high' });
    } else if (ageDays >= 30) {
      issues.push({ itemId: item.id, itemName: name, issue: `Rotation review due in ${ageDays}d`, severity: 'low' });
    }
  }

  return issues;
}
