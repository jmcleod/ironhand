import { useState } from 'react';
import { VaultItem, itemName, itemType, itemUpdatedAt, userFields, SENSITIVE_FIELDS, itemAttachments, formatFileSize } from '@/types/vault';
import { useVault } from '@/contexts/VaultContext';
import { Eye, EyeOff, Trash2, Copy, Check, KeyRound, StickyNote, CreditCard, Box, Pencil, History, AlertTriangle, Paperclip, Download } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { useToast } from '@/hooks/use-toast';
import EditItemDialog from '@/components/EditItemDialog';
import ItemHistoryDialog from '@/components/ItemHistoryDialog';
import TotpCodeDisplay from '@/components/TotpCodeDisplay';
import PasswordStrengthIndicator from '@/components/PasswordStrengthIndicator';
import { isValidTOTPSecret } from '@/lib/totp';
import { assessPasswordStrength } from '@/lib/password-strength';

interface ItemCardProps {
  item: VaultItem;
  vaultId: string;
  onRequestEdit?: (item: VaultItem) => void;
}

export default function ItemCard({ item, vaultId, onRequestEdit }: ItemCardProps) {
  const { removeItem } = useVault();
  const { toast } = useToast();
  const [revealedFields, setRevealedFields] = useState<Set<string>>(new Set());
  const [copiedField, setCopiedField] = useState<string | null>(null);
  const [editOpen, setEditOpen] = useState(false);
  const [historyOpen, setHistoryOpen] = useState(false);

  const type = itemType(item);
  const name = itemName(item);
  const updatedAt = itemUpdatedAt(item);
  const fields = userFields(item);
  const passwordStrength = fields.password ? assessPasswordStrength(fields.password) : null;
  const hasWeakPassword = !!passwordStrength?.isWeak;

  const isSensitive = (fieldName: string) => SENSITIVE_FIELDS.has(fieldName);

  const toggleReveal = (fieldName: string) => {
    setRevealedFields(prev => {
      const next = new Set(prev);
      if (next.has(fieldName)) {
        next.delete(fieldName);
      } else {
        next.add(fieldName);
      }
      return next;
    });
  };

  const handleCopy = (fieldName: string, value: string) => {
    navigator.clipboard.writeText(value);
    setCopiedField(fieldName);
    setTimeout(() => setCopiedField(null), 2000);
  };

  const handleDownload = (filename: string, base64Data: string, contentType: string) => {
    try {
      const binary = atob(base64Data);
      const bytes = new Uint8Array(binary.length);
      for (let i = 0; i < binary.length; i++) {
        bytes[i] = binary.charCodeAt(i);
      }
      const blob = new Blob([bytes], { type: contentType });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = filename;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch {
      toast({ title: 'Download failed', description: 'Could not decode attachment.', variant: 'destructive' });
    }
  };

  const handleDelete = async () => {
    if (confirm('Delete this item?')) {
      try {
        await removeItem(vaultId, item.id);
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to delete item.';
        toast({ title: 'Delete failed', description: msg, variant: 'destructive' });
      }
    }
  };

  const handleEdit = () => {
    if (onRequestEdit) {
      onRequestEdit(item);
      return;
    }
    setEditOpen(true);
  };

  const typeIcon = () => {
    switch (type) {
      case 'login': return <KeyRound className="h-4 w-4 text-primary" />;
      case 'note': return <StickyNote className="h-4 w-4 text-primary" />;
      case 'card': return <CreditCard className="h-4 w-4 text-primary" />;
      case 'custom': return <Box className="h-4 w-4 text-primary" />;
    }
  };

  const typeLabel = () => {
    switch (type) {
      case 'login': return 'Login';
      case 'note': return 'Note';
      case 'card': return 'Card';
      case 'custom': return 'Custom';
    }
  };

  const maskValue = (value: string) => {
    return '\u2022'.repeat(Math.min(value.length, 20));
  };

  const formatFieldLabel = (key: string) => {
    return key.replace(/_/g, ' ').replace(/\b\w/g, c => c.toUpperCase());
  };

  const renderFieldValue = (key: string, value: string) => {
    const sensitive = isSensitive(key);
    const revealed = revealedFields.has(key);

    if (key === 'url' && value) {
      return (
        <a href={value.startsWith('http') ? value : `https://${value}`} target="_blank" rel="noopener noreferrer" className="text-primary hover:underline text-sm break-all">
          {value}
        </a>
      );
    }

    if (key === 'content') {
      return (
        <pre className="text-sm text-foreground whitespace-pre-wrap font-sans break-all">
          {value}
        </pre>
      );
    }

    if (sensitive && !revealed) {
      return <span className="font-mono text-sm text-muted-foreground">{maskValue(value)}</span>;
    }

    return <span className="text-sm text-foreground break-all">{value}</span>;
  };

  const renderTotpField = (secret: string) => {
    const revealed = revealedFields.has('totp');
    return (
      <div key="totp" className="py-1.5">
        {/* Live TOTP code */}
        <div className="flex items-center gap-2 group">
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
            TOTP Code
          </span>
          <div className="flex-1 min-w-0">
            <TotpCodeDisplay secret={secret} />
          </div>
        </div>
        {/* Raw secret (hidden by default, togglable) */}
        <div className="flex items-center gap-2 mt-1 group">
          <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
            Totp Secret
          </span>
          <div className="flex-1 min-w-0">
            {revealed ? (
              <span className="text-sm text-foreground break-all font-mono">{secret}</span>
            ) : (
              <span className="font-mono text-sm text-muted-foreground">{maskValue(secret)}</span>
            )}
          </div>
          <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
            <Button variant="ghost" size="icon" onClick={() => toggleReveal('totp')} className="h-7 w-7">
              {revealed ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </Button>
            <Button variant="ghost" size="icon" onClick={() => handleCopy('totp', secret)} className="h-7 w-7">
              {copiedField === 'totp' ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
            </Button>
          </div>
        </div>
      </div>
    );
  };

  const renderField = (key: string, value: string) => {
    // TOTP fields get special rendering with live code generation
    if (key === 'totp' && value && isValidTOTPSecret(value)) {
      return renderTotpField(value);
    }
    if (key === 'password') {
      const sensitive = isSensitive(key);
      return (
        <div key={key} className="py-1.5 group">
          <div className="flex items-center gap-2">
            <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
              {formatFieldLabel(key)}
            </span>
            <div className="flex-1 min-w-0">
              {renderFieldValue(key, value)}
              <PasswordStrengthIndicator password={value} showGuidance={false} className="max-w-[280px]" />
            </div>
            <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
              {sensitive && (
                <Button variant="ghost" size="icon" onClick={() => toggleReveal(key)} className="h-7 w-7">
                  {revealedFields.has(key) ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
              )}
              <Button variant="ghost" size="icon" onClick={() => handleCopy(key, value)} className="h-7 w-7">
                {copiedField === key ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
              </Button>
            </div>
          </div>
        </div>
      );
    }

    const sensitive = isSensitive(key);
    return (
      <div key={key} className="flex items-center gap-2 py-1.5 group">
        <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider min-w-[100px] shrink-0">
          {formatFieldLabel(key)}
        </span>
        <div className="flex-1 min-w-0">
          {renderFieldValue(key, value)}
        </div>
        <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity shrink-0">
          {sensitive && (
            <Button variant="ghost" size="icon" onClick={() => toggleReveal(key)} className="h-7 w-7">
              {revealedFields.has(key) ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
            </Button>
          )}
          <Button variant="ghost" size="icon" onClick={() => handleCopy(key, value)} className="h-7 w-7">
            {copiedField === key ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>
    );
  };

  const fieldEntries = Object.entries(fields);

  return (
    <>
      <div className="rounded-xl border border-border bg-card p-5 vault-card-hover">
        <div className="flex items-center justify-between mb-3">
          <div className="flex items-center gap-3">
            <div className="h-9 w-9 rounded-lg bg-accent flex items-center justify-center">
              {typeIcon()}
            </div>
            <div>
              <h3 className="font-medium text-foreground">{name}</h3>
              <span className="text-xs text-muted-foreground">
                {typeLabel()}
                {updatedAt && <> &middot; {new Date(updatedAt).toLocaleDateString()}</>}
              </span>
            </div>
          </div>
          <div className="flex items-center gap-0.5">
            <Button variant="ghost" size="icon" onClick={() => setHistoryOpen(true)} className="h-8 w-8" title="Version history">
              <History className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleEdit} className="h-8 w-8" title="Edit">
              <Pencil className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="icon" onClick={handleDelete} className="h-8 w-8 text-destructive hover:text-destructive" title="Delete">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
        {hasWeakPassword && (
          <div className="mb-3 rounded-lg border border-amber-300/40 bg-amber-500/10 px-3 py-2">
            <p className="text-xs text-amber-700 dark:text-amber-300 flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5" />
              Weak password detected for this item. Update it to a stronger password.
            </p>
          </div>
        )}
        {fieldEntries.length > 0 && (
          <div className="divide-y divide-border/50">
            {fieldEntries.map(([key, value]) => renderField(key, value))}
          </div>
        )}
        {(() => {
          const atts = itemAttachments(item);
          if (atts.length === 0) return null;
          return (
            <div className="mt-3 pt-3 border-t border-border/50">
              <span className="text-xs font-medium text-muted-foreground uppercase tracking-wider block mb-2">
                Attachments
              </span>
              <div className="space-y-1.5">
                {atts.map(({ filename, meta, dataFieldName }) => (
                  <div key={filename} className="flex items-center gap-2 py-1 group">
                    <Paperclip className="h-3.5 w-3.5 text-muted-foreground shrink-0" />
                    <span className="text-sm text-foreground flex-1 truncate">{filename}</span>
                    <span className="text-xs text-muted-foreground">{formatFileSize(meta.size)}</span>
                    <Button
                      variant="ghost"
                      size="icon"
                      className="h-7 w-7 opacity-0 group-hover:opacity-100 transition-opacity"
                      onClick={() => handleDownload(filename, item.fields[dataFieldName], meta.content_type)}
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

      {!onRequestEdit && (
        <EditItemDialog open={editOpen} onOpenChange={setEditOpen} vaultId={vaultId} item={item} />
      )}
      <ItemHistoryDialog open={historyOpen} onOpenChange={setHistoryOpen} vaultId={vaultId} item={item} />
    </>
  );
}
