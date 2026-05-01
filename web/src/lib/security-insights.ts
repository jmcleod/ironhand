import { itemName, itemType, itemUpdatedAt, userFields, Vault, VaultItem } from '@/types/vault';

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
