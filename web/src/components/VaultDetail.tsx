import { useEffect, useMemo, useState } from 'react';
import { Vault, ItemType } from '@/types/vault';
import { useVault } from '@/contexts/VaultContext';
import { ArrowLeft, Plus, Trash2, Share2, FileText, Search, X, KeyRound, StickyNote, CreditCard, Box } from 'lucide-react';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import ItemCard from '@/components/ItemCard';
import AddItemDialog from '@/components/AddItemDialog';
import ShareDialog from '@/components/ShareDialog';
import { useToast } from '@/hooks/use-toast';
import { searchItems } from '@/lib/search';

const TYPE_FILTERS: { value: ItemType | 'all'; label: string; icon?: React.ReactNode }[] = [
  { value: 'all', label: 'All' },
  { value: 'login', label: 'Login', icon: <KeyRound className="h-3 w-3" /> },
  { value: 'note', label: 'Note', icon: <StickyNote className="h-3 w-3" /> },
  { value: 'card', label: 'Card', icon: <CreditCard className="h-3 w-3" /> },
  { value: 'custom', label: 'Custom', icon: <Box className="h-3 w-3" /> },
];

interface VaultDetailProps {
  vault: Vault;
  onBack: () => void;
}

export default function VaultDetail({ vault, onBack }: VaultDetailProps) {
  const { deleteVault } = useVault();
  const { toast } = useToast();
  const [showAddItem, setShowAddItem] = useState(false);
  const [showShare, setShowShare] = useState(false);
  const [searchQuery, setSearchQuery] = useState('');
  const [debouncedQuery, setDebouncedQuery] = useState('');
  const [typeFilter, setTypeFilter] = useState<ItemType | 'all'>('all');

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
            <Button variant="ghost" size="sm" onClick={handleDelete} className="text-destructive hover:text-destructive">
              <Trash2 className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </header>

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
                {filteredItems.map(item => (
                  <ItemCard key={item.id} item={item} vaultId={vault.id} />
                ))}
              </div>
            )}
          </div>
        )}
      </main>

      <AddItemDialog open={showAddItem} onOpenChange={setShowAddItem} vaultId={vault.id} />
      <ShareDialog open={showShare} onOpenChange={setShowShare} vaultId={vault.id} sharedWith={vault.sharedWith} />
    </div>
  );
}
