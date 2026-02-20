import { useCallback, useEffect, useState } from 'react';
import { listAuditLogs, PaginationMeta } from '@/lib/api';
import { AuditEntry } from '@/types/vault';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { ChevronLeft, ChevronRight } from 'lucide-react';

interface AuditLogDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
}

const PAGE_SIZE = 25;

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
  }
}

export default function AuditLogDialog({ open, onOpenChange, vaultId }: AuditLogDialogProps) {
  const [entries, setEntries] = useState<AuditEntry[]>([]);
  const [pagination, setPagination] = useState<PaginationMeta | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);

  const fetchPage = useCallback(
    (pageOffset: number) => {
      setLoading(true);
      setError(null);
      listAuditLogs(vaultId, undefined, { limit: PAGE_SIZE, offset: pageOffset })
        .then((result) => {
          setEntries(result.data);
          setPagination(result.pagination);
          setOffset(pageOffset);
        })
        .catch((err) => {
          const msg = err instanceof Error ? err.message : 'Failed to load audit logs';
          setError(msg);
        })
        .finally(() => setLoading(false));
    },
    [vaultId],
  );

  useEffect(() => {
    if (!open) return;
    // Reset to first page when dialog opens.
    setOffset(0);
    fetchPage(0);
  }, [open, vaultId, fetchPage]);

  const currentPage = Math.floor(offset / PAGE_SIZE) + 1;
  const totalPages = pagination ? Math.max(1, Math.ceil(pagination.total_count / PAGE_SIZE)) : 1;

  const goToPage = (page: number) => {
    const newOffset = (page - 1) * PAGE_SIZE;
    fetchPage(newOffset);
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            Audit Log
            {pagination && pagination.total_count > 0 && (
              <span className="text-sm font-normal text-muted-foreground ml-2">
                ({pagination.total_count} {pagination.total_count === 1 ? 'entry' : 'entries'})
              </span>
            )}
          </DialogTitle>
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

        {/* Pagination controls — shown when there are multiple pages */}
        {pagination && totalPages > 1 && (
          <div className="flex items-center justify-between pt-2 border-t border-border">
            <Button
              variant="outline"
              size="sm"
              disabled={currentPage <= 1 || loading}
              onClick={() => goToPage(currentPage - 1)}
            >
              <ChevronLeft className="h-4 w-4 mr-1" />
              Previous
            </Button>
            <span className="text-xs text-muted-foreground">
              Page {currentPage} of {totalPages}
            </span>
            <Button
              variant="outline"
              size="sm"
              disabled={!pagination.has_more || loading}
              onClick={() => goToPage(currentPage + 1)}
            >
              Next
              <ChevronRight className="h-4 w-4 ml-1" />
            </Button>
          </div>
        )}

        <Button variant="outline" onClick={() => onOpenChange(false)}>
          Close
        </Button>
      </DialogContent>
    </Dialog>
  );
}
