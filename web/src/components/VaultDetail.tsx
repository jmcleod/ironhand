import { useEffect, useMemo, useState } from 'react';
import { Vault, ItemType, VaultItem, itemName, itemType } from '@/types/vault';
import { useVault } from '@/contexts/VaultContext';
import { CAInfo } from '@/types/vault';
import { ArrowLeft, Plus, Trash2, Share2, FileText, Search, X, KeyRound, StickyNote, CreditCard, Box, Shield, ScrollText, Download, Upload } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import ItemCard from '@/components/ItemCard';
import AddItemDialog from '@/components/AddItemDialog';
import ShareDialog from '@/components/ShareDialog';
import AuditLogDialog from '@/components/AuditLogDialog';
import EditItemDialog from '@/components/EditItemDialog';
import ExportVaultDialog from '@/components/ExportVaultDialog';
import ImportVaultDialog from '@/components/ImportVaultDialog';
import InitCADialog from '@/components/InitCADialog';
import IssueCertDialog from '@/components/IssueCertDialog';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { useToast } from '@/hooks/use-toast';
import { searchItems } from '@/lib/search';
import { getItem as apiGetItem, getCAInfo, getCACert, getCRL } from '@/lib/api';

const TYPE_FILTERS: { value: ItemType | 'all'; label: string; icon?: React.ReactNode }[] = [
  { value: 'all', label: 'All' },
  { value: 'login', label: 'Login', icon: <KeyRound className="h-3 w-3" /> },
  { value: 'note', label: 'Note', icon: <StickyNote className="h-3 w-3" /> },
  { value: 'card', label: 'Card', icon: <CreditCard className="h-3 w-3" /> },
  { value: 'certificate', label: 'Cert', icon: <Shield className="h-3 w-3" /> },
  { value: 'custom', label: 'Custom', icon: <Box className="h-3 w-3" /> },
];

interface VaultDetailProps {
  vault: Vault;
  onBack: () => void;
}

export default function VaultDetail({ vault, onBack }: VaultDetailProps) {
  const { deleteVault, refresh } = useVault();
  const { toast } = useToast();
  const [showAddItem, setShowAddItem] = useState(false);
  const [showShare, setShowShare] = useState(false);
  const [showAudit, setShowAudit] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ItemType | 'all'>('all');
  const [selectedItemId, setSelectedItemId] = useState<string | null>(null);
  const [selectedItem, setSelectedItem] = useState<VaultItem | null>(null);
  const [itemViewOpen, setItemViewOpen] = useState(false);
  const [itemLoading, setItemLoading] = useState(false);
  const [editFromLightboxOpen, setEditFromLightboxOpen] = useState(false);
  const [editingItem, setEditingItem] = useState<VaultItem | null>(null);
  const [showExport, setShowExport] = useState(false);
  const [showImport, setShowImport] = useState(false);
  const [caInfo, setCAInfo] = useState<CAInfo | null>(null);
  const [showInitCA, setShowInitCA] = useState(false);
  const [showIssueCert, setShowIssueCert] = useState(false);

  // Fetch CA info on mount / refresh.
  const refreshCAInfo = () => {
    getCAInfo(vault.id).then(setCAInfo).catch(() => setCAInfo(null));
  };
  useEffect(() => { refreshCAInfo(); }, [vault.id]);

  const handleDownloadCACert = async () => {
    try {
      const pem = await getCACert(vault.id);
      const blob = new Blob([pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'ca-cert.pem';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to download CA certificate.';
      toast({ title: 'Download failed', description: msg, variant: 'destructive' });
    }
  };

  const handleDownloadCRL = async () => {
    try {
      const pem = await getCRL(vault.id);
      const blob = new Blob([pem], { type: 'application/x-pem-file' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'crl.pem';
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
      URL.revokeObjectURL(url);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to generate CRL.';
      toast({ title: 'Download failed', description: msg, variant: 'destructive' });
    }
  };

  // Debounce the search input.
  useEffect(() => {
    const timer = setTimeout(() => setDebouncedQuery(searchQuery), 200);
    return () => clearTimeout(timer);
  }, [searchQuery]);

  const isFilterActive = debouncedQuery.trim() !== '' || typeFilter !== 'all';

  const filteredItems = useMemo(() => {
    if (!isFilterActive) return vault.items;
    return searchItems([vault], debouncedQuery, typeFilter).map((r) => r.item);
  }, [vault, debouncedQuery, typeFilter, isFilterActive]);

  useEffect(() => {
    if (selectedItemId && !filteredItems.some((item) => item.id === selectedItemId)) {
      setSelectedItemId(null);
      setSelectedItem(null);
      setItemViewOpen(false);
    }
  }, [filteredItems, selectedItemId]);

  const iconForType = (type: ItemType) => {
    switch (type) {
      case 'login':
        return <KeyRound className="h-4 w-4" />;
      case 'note':
        return <StickyNote className="h-4 w-4" />;
      case 'card':
        return <CreditCard className="h-4 w-4" />;
      case 'certificate':
        return <Shield className="h-4 w-4" />;
      case 'custom':
        return <Box className="h-4 w-4" />;
    }
  };

  const openItemLightbox = async (itemId: string) => {
    setSelectedItemId(itemId);
    setItemLoading(true);
    try {
      const fields = await apiGetItem(vault.id, itemId);
      setSelectedItem({ id: itemId, fields });
      setItemViewOpen(true);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to load item details.';
      toast({ title: 'Load failed', description: msg, variant: 'destructive' });
    } finally {
      setItemLoading(false);
    }
  };

  const handleDelete = async () => {
    if (confirm('Delete this vault and all its items?')) {
      try {
        await deleteVault(vault.id);
        onBack();
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Failed to delete vault.';
        toast({ title: 'Delete failed', description: msg, variant: 'destructive' });
      }
    }
  };

  return (
    <div className="min-h-screen bg-background">
      <header className="border-b border-border bg-card/50 backdrop-blur-sm sticky top-0 z-10">
        <div className="max-w-4xl mx-auto px-6 py-4 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Button variant="ghost" size="icon" onClick={onBack}>
              <ArrowLeft className="h-4 w-4" />
            </Button>
            <div>
              <h1 className="font-bold text-lg leading-none">{vault.name}</h1>
              <p className="text-xs text-muted-foreground mt-0.5">{vault.description}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => setShowShare(true)}>
              <Share2 className="h-4 w-4 mr-1" />
              Share
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowAddItem(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Add Item
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowAudit(true)}>
              <ScrollText className="h-4 w-4 mr-1" />
              Audit
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowExport(true)}>
              <Download className="h-4 w-4 mr-1" />
              Export
            </Button>
            <Button variant="outline" size="sm" onClick={() => setShowImport(true)}>
              <Upload className="h-4 w-4 mr-1" />
              Import
            </Button>
            {caInfo?.is_ca ? (
              <>
                <Button variant="outline" size="sm" onClick={() => setShowIssueCert(true)}>
                  <Shield className="h-4 w-4 mr-1" />
                  Issue Cert
                </Button>
                <Button variant="outline" size="sm" onClick={handleDownloadCACert}>
                  <Download className="h-4 w-4 mr-1" />
                  CA Cert
                </Button>
                <Button variant="outline" size="sm" onClick={handleDownloadCRL}>
                  <Download className="h-4 w-4 mr-1" />
                  CRL
                </Button>
              </>
            ) : (
              <Button variant="outline" size="sm" onClick={() => setShowInitCA(true)}>
                <Shield className="h-4 w-4 mr-1" />
                Init CA
              </Button>
            )}
            <Button variant="ghost" size="sm" onClick={handleDelete} className="text-destructive hover:text-destructive">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

      {caInfo?.is_ca && (
        <div className="max-w-4xl mx-auto px-6 pt-4">
          <div className="rounded-lg border border-primary/20 bg-primary/5 px-4 py-3">
            <div className="flex items-center gap-2 text-sm">
              <Shield className="h-4 w-4 text-primary" />
              <span className="font-medium">Certificate Authority</span>
              <span className="text-muted-foreground">&middot;</span>
              <span className="text-muted-foreground">{caInfo.subject}</span>
              <span className="text-muted-foreground">&middot;</span>
              <span className="text-muted-foreground">{caInfo.cert_count} cert{caInfo.cert_count !== 1 ? 's' : ''} issued</span>
            </div>
          </div>
        </div>
      )}

      <main className="max-w-4xl mx-auto px-6 py-8">
        {vault.items.length === 0 ? (
          <div className="flex flex-col items-center justify-center py-20 animate-fade-in">
            <div className="h-16 w-16 rounded-2xl bg-muted flex items-center justify-center mb-4">
              <FileText className="h-8 w-8 text-muted-foreground" />
            </div>
            <h2 className="text-lg font-semibold mb-1">No Items</h2>
            <p className="text-sm text-muted-foreground mb-4">Add your first secret item to this vault.</p>
            <Button onClick={() => setShowAddItem(true)}>
              <Plus className="h-4 w-4 mr-2" />
              Add Item
            </Button>
          </div>
        ) : (
          <div className="animate-fade-in">
            {/* Search and filter */}
            <div className="mb-5 space-y-3">
              <div className="relative">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Filter items..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9 pr-9 bg-muted border-border"
                />
                {searchQuery && (
                  <button
                    onClick={() => { setSearchQuery(''); setDebouncedQuery(''); }}
                    className="absolute right-3 top-1/2 -translate-y-1/2 text-muted-foreground hover:text-foreground"
                  >
                    <X className="h-4 w-4" />
                  </button>
                )}
              </div>
              <div className="flex items-center gap-1.5">
                {TYPE_FILTERS.map((f) => (
                  <Button
                    key={f.value}
                    variant={typeFilter === f.value ? 'default' : 'ghost'}
                    size="sm"
                    className="h-7 text-xs px-2.5 gap-1"
                    onClick={() => setTypeFilter(f.value)}
                  >
                    {f.icon}
                    {f.label}
                  </Button>
                ))}
              </div>
            </div>

            {/* Items list */}
            {filteredItems.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12">
                <Search className="h-8 w-8 text-muted-foreground mb-3" />
                <p className="text-sm text-muted-foreground">No items match your filter.</p>
              </div>
            ) : (
              <div className="space-y-3">
                {isFilterActive && (
                  <p className="text-xs text-muted-foreground">
                    {filteredItems.length} of {vault.items.length} items
                  </p>
                )}
                <div className="rounded-xl border border-border bg-card divide-y divide-border/50">
                  {filteredItems.map((item) => (
                    <button
                      key={item.id}
                      type="button"
                      className={`w-full text-left px-4 py-3 hover:bg-muted/40 transition-colors ${
                        selectedItemId === item.id ? 'bg-muted/50' : ''
                      }`}
                      onClick={() => void openItemLightbox(item.id)}
                    >
                      <div className="flex items-center gap-2 text-foreground">
                        <span className="text-muted-foreground">{iconForType(itemType(item))}</span>
                        <p className="text-sm font-medium">{itemName(item)}</p>
                      </div>
                    </button>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </main>

      <AddItemDialog open={showAddItem} onOpenChange={setShowAddItem} vaultId={vault.id} />
      <ShareDialog open={showShare} onOpenChange={setShowShare} vaultId={vault.id} sharedWith={vault.sharedWith} />
      <AuditLogDialog open={showAudit} onOpenChange={setShowAudit} vaultId={vault.id} />
      <Dialog open={itemViewOpen} onOpenChange={(open) => { setItemViewOpen(open); if (!open) setSelectedItem(null); }}>
        <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle>{selectedItem ? itemName(selectedItem) : 'Item'}</DialogTitle>
          </DialogHeader>
          {itemLoading ? (
            <p className="text-sm text-muted-foreground">Loading item...</p>
          ) : selectedItem ? (
            <ItemCard
              item={selectedItem}
              vaultId={vault.id}
              onRequestEdit={(item) => {
                setEditingItem(item);
                setItemViewOpen(false);
                setEditFromLightboxOpen(true);
              }}
            />
          ) : (
            <p className="text-sm text-muted-foreground">No item selected.</p>
          )}
        </DialogContent>
      </Dialog>
      {editingItem && (
        <EditItemDialog
          open={editFromLightboxOpen}
          onOpenChange={(open) => {
            setEditFromLightboxOpen(open);
            if (!open) setEditingItem(null);
          }}
          vaultId={vault.id}
          item={editingItem}
        />
      )}
      <ExportVaultDialog open={showExport} onOpenChange={setShowExport} vaultId={vault.id} vaultName={vault.name} />
      <ImportVaultDialog open={showImport} onOpenChange={setShowImport} vaultId={vault.id} />
      <InitCADialog open={showInitCA} onOpenChange={setShowInitCA} vaultId={vault.id} onSuccess={() => { refreshCAInfo(); refresh(); }} />
      <IssueCertDialog open={showIssueCert} onOpenChange={setShowIssueCert} vaultId={vault.id} onSuccess={() => { refreshCAInfo(); refresh(); }} />
    </div>
  );
}
