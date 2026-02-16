import { useCallback, useEffect, useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { getItemHistory, getHistoryVersion } from '@/lib/api';
import { HistoryEntry, VaultItem, itemName, userFields, SENSITIVE_FIELDS } from '@/types/vault';
import { useToast } from '@/hooks/use-toast';
import { ArrowLeft, Clock, Eye, EyeOff, Copy, Check, Paperclip, Download } from 'lucide-react';
import { itemAttachments, formatFileSize, attachmentFieldName, AttachmentInfo } from '@/types/vault';

interface ItemHistoryDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  item: VaultItem;
}

export default function ItemHistoryDialog({ open, onOpenChange, vaultId, item }: ItemHistoryDialogProps) {
  const { toast } = useToast();
  const [history, setHistory] = useState<HistoryEntry[]>([]);
  const [loading, setLoading] = useState(false);
  const [selectedVersion, setSelectedVersion] = useState<number | null>(null);
  const [versionFields, setVersionFields] = useState<Record<string, string> | null>(null);
  const [loadingVersion, setLoadingVersion] = useState(false);
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);

  const currentFields = userFields(item);

  const fetchHistory = useCallback(async () => {
    setLoading(true);
    try {
      const entries = await getItemHistory(vaultId, item.id);
      setHistory(entries);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load history.';
      toast({ title: 'History error', description: msg, variant: 'destructive' });
    } finally {
      setLoading(false);
    }
  }, [vaultId, item.id, toast]);

  useEffect(() => {
    if (open) {
      setSelectedVersion(null);
      setVersionFields(null);
      setRevealedFields(new Set());
      fetchHistory();
    }
  }, [open, fetchHistory]);

  const handleSelectVersion = async (version: number) => {
    setSelectedVersion(version);
    setLoadingVersion(true);
    setRevealedFields(new Set());
    try {
      const fields = await getHistoryVersion(vaultId, item.id, version);
      setVersionFields(fields);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load version.';
      toast({ title: 'Version error', description: msg, variant: 'destructive' });
      setSelectedVersion(null);
    } finally {
      setLoadingVersion(false);
    }
  };

  const toggleReveal = (fieldName: string) => {
    setRevealedFields(prev => {
      const next = new Set(prev);
      if (next.has(fieldName)) next.delete(fieldName);
      else next.add(fieldName);
      return next;
    });
  };

  const handleCopy = (fieldName: string, value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDownloadAttachment = (filename: string, base64Data: string, contentType: string) => {
    try {
      const binary = atob(base64Data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
      const blob = new Blob([bytes], { type: contentType || 'application/octet-stream' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      toast({ title: 'Download failed', description: 'Could not decode attachment data.', variant: 'destructive' });
    }
  };

  const versionAttachments = (fields: Record<string, string>): AttachmentInfo[] => {
    const syntheticItem = { id: '', fields };
    return itemAttachments(syntheticItem);
  };

  const isSensitive = (name: string) => SENSITIVE_FIELDS.has(name);
  const maskValue = (value: string) => '\u2022'.repeat(Math.min(value.length, 20));
  const formatFieldLabel = (key: string) => key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());

  // Filter out _ prefixed metadata fields from version fields
  const filterUserFields = (fields: Record<string, string>) => {
    const result: Record<string, string> = {};
    for (const [k, v] of Object.entries(fields)) {
      if (!k.startsWith('_')) result[k] = v;
    }
    return result;
  };

  const getFieldChangeStatus = (fieldName: string, oldValue: string): 'added' | 'removed' | 'changed' | 'unchanged' => {
    const currentValue = currentFields[fieldName];
    if (currentValue === undefined) return 'removed';
    if (currentValue === oldValue) return 'unchanged';
    return 'changed';
  };

  const getNewFieldsInCurrent = (): string[] => {
    if (!versionFields) return [];
    const filtered = filterUserFields(versionFields);
    return Object.keys(currentFields).filter(k => !(k in filtered));
  };

  const renderVersionList = () => {
    if (loading) {
      return <p className="text-sm text-muted-foreground text-center py-8">Loading history...</p>;
    }
    if (history.length === 0) {
      return <p className="text-sm text-muted-foreground text-center py-8">No version history available.</p>;
    }
    return (
      <div className="space-y-2">
        {history.map((entry) => (
          <button
            key={entry.version}
            onClick={() => handleSelectVersion(entry.version)}
            className="w-full text-left p-3 rounded-lg border border-border hover:bg-accent/50 transition-colors"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">Version {entry.version}</span>
              </div>
              <span className="text-xs text-muted-foreground">
                {new Date(entry.updated_at).toLocaleString()}
              </span>
            </div>
            {entry.updated_by && (
              <span className="text-xs text-muted-foreground mt-1 block">
                Changed by {entry.updated_by}
              </span>
            )}
          </button>
        ))}
      </div>
    );
  };

  const renderVersionDetail = () => {
    if (loadingVersion) {
      return <p className="text-sm text-muted-foreground text-center py-8">Loading version...</p>;
    }
    if (!versionFields) return null;

    const filtered = filterUserFields(versionFields);
    const newFields = getNewFieldsInCurrent();

    return (
      <div className="space-y-3">
        <div className="flex items-center gap-2 mb-4">
          <Button variant="ghost" size="icon" onClick={() => { setSelectedVersion(null); setVersionFields(null); }} className="h-8 w-8">
            <ArrowLeft className="h-4 w-4" />
          </Button>
          <h3 className="text-sm font-medium">Version {selectedVersion}</h3>
        </div>

        <div className="divide-y divide-border/50">
          {Object.entries(filtered).map(([key, value]) => {
            const status = getFieldChangeStatus(key, value);
            const sensitive = isSensitive(key);
            const revealed = revealedFields.has(key);

            return (
              <div key={key} className="flex items-center gap-2 py-2 group">
                <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
                  {formatFieldLabel(key)}
                </span>
                <div className="flex-1 min-w-0">
                  {sensitive && !revealed ? (
                    <span className="font-mono text-sm text-muted-foreground">{maskValue(value)}</span>
                  ) : (
                    <span className="text-sm text-foreground break-all">{value}</span>
                  )}
                </div>
                {status === 'changed' && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-yellow-500/10 text-yellow-600 dark:text-yellow-400 shrink-0">changed</span>
                )}
                {status === 'removed' && (
                  <span className="text-xs px-1.5 py-0.5 rounded bg-red-500/10 text-red-600 dark:text-red-400 shrink-0">removed</span>
                )}
                <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
                  {sensitive && (
                    <Button variant="ghost" size="icon" onClick={() => toggleReveal(key)} className="h-7 w-7">
                      {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                    </Button>
                  )}
                  <Button variant="ghost" size="icon" onClick={() => handleCopy(key, value)} className="h-7 w-7">
                    {copiedField === key ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
                  </Button>
                </div>
              </div>
            );
          })}

          {newFields.map((key) => (
            <div key={key} className="flex items-center gap-2 py-2">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
                {formatFieldLabel(key)}
              </span>
              <div className="flex-1 min-w-0">
                <span className="text-sm text-muted-foreground italic">not present in this version</span>
              </div>
              <span className="text-xs px-1.5 py-0.5 rounded bg-green-500/10 text-green-600 dark:text-green-400 shrink-0">added since</span>
            </div>
          ))}
        </div>

        {(() => {
          const atts = versionAttachments(versionFields);
          if (atts.length === 0) return null;
          return (
            <div className="mt-4">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block">Attachments</span>
              <div className="space-y-1.5">
                {atts.map((att) => (
                  <div key={att.filename} className="flex items-center gap-2 p-2 rounded bg-muted group">
                    <Paperclip className="h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="text-sm flex-1 truncate">{att.filename}</span>
                    <span className="text-xs text-muted-foreground">{formatFileSize(att.meta.size)}</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                      onClick={() => handleDownloadAttachment(att.filename, versionFields[attachmentFieldName(att.filename)], att.meta.content_type)}
                      title="Download"
                    >
                      <Download className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          );
        })()}
      </div>
    );
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border sm:max-w-lg max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>
            {selectedVersion ? 'Version Detail' : `History \u2014 ${itemName(item)}`}
          </DialogTitle>
        </DialogHeader>
        {selectedVersion ? renderVersionDetail() : renderVersionList()}
      </DialogContent>
    </Dialog>
  );
}
