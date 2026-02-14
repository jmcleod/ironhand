import { useState } from 'react';
import { Vault, ItemType } from '@/types/vault';
import { useVault } from '@/contexts/VaultContext';
import { ArrowLeft, Plus, Trash2, Share2, FileText, Image, Mail } from 'lucide-react';
import { Button } from '@/components/ui/button';
import ItemCard from '@/components/ItemCard';
import AddItemDialog from '@/components/AddItemDialog';
import ShareDialog from '@/components/ShareDialog';
import { useToast } from '@/hooks/use-toast';

interface VaultDetailProps {
  vault: Vault;
  onBack: () => void;
}

export default function VaultDetail({ vault, onBack }: VaultDetailProps) {
  const { deleteVault } = useVault();
  const { toast } = useToast();
  const [showAddItem, setShowAddItem] = useState(false);
  const [showShare, setShowShare] = useState(false);

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

  const typeIcon = (type: ItemType) => {
    switch (type) {
      case 'text': return <FileText className="h-4 w-4" />;
      case 'image': return <Image className="h-4 w-4" />;
      case 'email': return <Mail className="h-4 w-4" />;
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
          <div className="space-y-3 animate-fade-in">
            {vault.items.map(item => (
              <ItemCard key={item.id} item={item} vaultId={vault.id} />
            ))}
          </div>
        )}
      </main>

      <AddItemDialog open={showAddItem} onOpenChange={setShowAddItem} vaultId={vault.id} />
      <ShareDialog open={showShare} onOpenChange={setShowShare} vaultId={vault.id} sharedWith={vault.sharedWith} />
    </div>
  );
}
