import { useEffect, useState } from 'react';
import { listAuditLogs } from '@/lib/api';
import { AuditEntry } from '@/types/vault';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';

interface AuditLogDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
}

function actionLabel(action: AuditEntry['action']) {
  switch (action) {
    case 'item_accessed':
      return 'Accessed';
    case 'item_created':
      return 'Created';
    case 'item_updated':
      return 'Updated';
    case 'item_deleted':
      return 'Deleted';
    case 'vault_exported':
      return 'Vault Exported';
    case 'vault_imported':
      return 'Vault Imported';
  }
}

export default function AuditLogDialog({ open, onOpenChange, vaultId }: AuditLogDialogProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!open) return;
    setLoading(true);
    setError(null);
    listAuditLogs(vaultId)
      .then(setEntries)
      .catch((err) => {
        const msg = err instanceof Error ? err.message : 'Failed to load audit logs';
        setError(msg);
      })
      .finally(() => setLoading(false));
  }, [open, vaultId]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Audit Log</DialogTitle>
        </DialogHeader>
        {loading ? (
          <p className="text-sm text-muted-foreground">Loading audit entries...</p>
        ) : error ? (
          <p className="text-sm text-destructive">{error}</p>
        ) : entries.length === 0 ? (
          <p className="text-sm text-muted-foreground">No audit entries for this vault yet.</p>
        ) : (
          <div className="space-y-2">
            {entries.map((entry) => (
              <div key={entry.id} className="rounded-lg border border-border p-3 bg-muted/30">
                <div className="flex items-center justify-between gap-3">
                  <p className="text-sm font-medium">{actionLabel(entry.action)}</p>
                  <p className="text-xs text-muted-foreground">
                    {new Date(entry.created_at).toLocaleString()}
                  </p>
                </div>
                <p className="text-xs text-muted-foreground mt-1">
                  Item: <span className="font-mono">{entry.item_id}</span>
                </p>
                <p className="text-xs text-muted-foreground">
                  Member: <span className="font-mono">{entry.member_id}</span>
                </p>
              </div>
            ))}
          </div>
        )}
        <Button variant="outline" onClick={() => onOpenChange(false)}>
          Close
        </Button>
      </DialogContent>
    </Dialog>
  );
}
