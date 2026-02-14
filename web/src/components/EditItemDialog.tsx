import { useEffect, useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { VaultItem, itemName, itemType, userFields, ItemType } from '@/types/vault';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import PasswordGenerator from '@/components/PasswordGenerator';
import { useToast } from '@/hooks/use-toast';
import { Eye, EyeOff, Plus, Wand2, X } from 'lucide-react';

interface EditItemDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  item: VaultItem;
}

interface CustomField {
  key: string;
  value: string;
}

const LABEL = 'text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block';
const FIELD = 'bg-muted border-border';

export default function EditItemDialog({ open, onOpenChange, vaultId, item }: EditItemDialogProps) {
  const { updateItem } = useVault();
  const { toast } = useToast();

  const type = itemType(item);
  const [name, setName] = useState('');
  const [saving, setSaving] = useState(false);
  const [showPassword, setShowPassword] = useState(false);
  const [showGenerator, setShowGenerator] = useState(false);

  // Login fields
  const [username, setUsername] = useState('');
  const [password, setPassword] = useState('');
  const [url, setUrl] = useState('');
  const [totp, setTotp] = useState('');
  const [notes, setNotes] = useState('');

  // Note fields
  const [content, setContent] = useState('');

  // Card fields
  const [cardholder, setCardholder] = useState('');
  const [cardNumber, setCardNumber] = useState('');
  const [expiry, setExpiry] = useState('');
  const [cvv, setCvv] = useState('');
  const [cardNotes, setCardNotes] = useState('');

  // Custom fields
  const [customFields, setCustomFields] = useState<CustomField[]>([{ key: '', value: '' }]);

  // Populate form from item when opening
  useEffect(() => {
    if (!open) return;
    const fields = userFields(item);
    setName(itemName(item));
    setShowPassword(false);
    setShowGenerator(false);

    switch (type) {
      case 'login':
        setUsername(fields.username || '');
        setPassword(fields.password || '');
        setUrl(fields.url || '');
        setTotp(fields.totp || '');
        setNotes(fields.notes || '');
        break;
      case 'note':
        setContent(fields.content || '');
        break;
      case 'card':
        setCardholder(fields.cardholder || '');
        setCardNumber(fields.card_number || '');
        setExpiry(fields.expiry || '');
        setCvv(fields.cvv || '');
        setCardNotes(fields.notes || '');
        break;
      case 'custom': {
        const entries = Object.entries(fields);
        setCustomFields(entries.length > 0 ? entries.map(([key, value]) => ({ key, value })) : [{ key: '', value: '' }]);
        break;
      }
    }
  }, [open, item, type]);

  const buildFields = (): Record<string, string> => {
    switch (type) {
      case 'login': {
        const f: Record<string, string> = {};
        if (username) f.username = username;
        if (password) f.password = password;
        if (url) f.url = url;
        if (totp) f.totp = totp;
        if (notes) f.notes = notes;
        return f;
      }
      case 'note':
        return content ? { content } : {};
      case 'card': {
        const f: Record<string, string> = {};
        if (cardholder) f.cardholder = cardholder;
        if (cardNumber) f.card_number = cardNumber;
        if (expiry) f.expiry = expiry;
        if (cvv) f.cvv = cvv;
        if (cardNotes) f.notes = cardNotes;
        return f;
      }
      case 'custom': {
        const f: Record<string, string> = {};
        for (const cf of customFields) {
          if (cf.key.trim() && cf.value.trim()) {
            f[cf.key.trim()] = cf.value.trim();
          }
        }
        return f;
      }
    }
  };

  const canSave = () => {
    if (!name.trim()) return false;
    const fields = buildFields();
    return Object.keys(fields).length > 0;
  };

  const handleSave = async () => {
    if (!canSave()) return;
    setSaving(true);
    try {
      await updateItem(vaultId, item.id, { ...buildFields(), _name: name.trim() });
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to update item.';
      toast({ title: 'Update failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  const addCustomField = () => {
    setCustomFields([...customFields, { key: '', value: '' }]);
  };

  const removeCustomField = (index: number) => {
    setCustomFields(customFields.filter((_, i) => i !== index));
  };

  const updateCustomField = (index: number, field: 'key' | 'value', value: string) => {
    const updated = [...customFields];
    updated[index] = { ...updated[index], [field]: value };
    setCustomFields(updated);
  };

  const typeLabel = (t: ItemType) => {
    switch (t) {
      case 'login': return 'Login';
      case 'note': return 'Note';
      case 'card': return 'Card';
      case 'custom': return 'Custom';
    }
  };

  const renderLoginFields = () => (
    <>
      <div>
        <label className={LABEL}>Username</label>
        <Input value={username} onChange={e => setUsername(e.target.value)} placeholder="username or email" className={FIELD} />
      </div>
      <div>
        <label className={LABEL}>Password</label>
        <div className="relative">
          <Input
            type={showPassword ? 'text' : 'password'}
            value={password}
            onChange={e => setPassword(e.target.value)}
            placeholder="password"
            className={`${FIELD} pr-20`}
          />
          <div className="absolute right-0 top-0 h-full flex items-center">
            <Popover open={showGenerator} onOpenChange={setShowGenerator}>
              <PopoverTrigger asChild>
                <Button type="button" variant="ghost" size="icon" className="h-full w-10" title="Generate password">
                  <Wand2 className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-80 p-4 bg-card border-border" align="end" side="bottom">
                <PasswordGenerator onUse={(value) => { setPassword(value); setShowPassword(true); setShowGenerator(false); }} />
              </PopoverContent>
            </Popover>
            <Button type="button" variant="ghost" size="icon" className="h-full w-10" onClick={() => setShowPassword(!showPassword)}>
              {showPassword ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
            </Button>
          </div>
        </div>
      </div>
      <div>
        <label className={LABEL}>URL</label>
        <Input value={url} onChange={e => setUrl(e.target.value)} placeholder="https://example.com" className={FIELD} />
      </div>
      <div>
        <label className={LABEL}>TOTP Secret</label>
        <Input value={totp} onChange={e => setTotp(e.target.value)} placeholder="TOTP secret key (optional)" className={`${FIELD} font-mono`} />
      </div>
      <div>
        <label className={LABEL}>Notes</label>
        <Textarea value={notes} onChange={e => setNotes(e.target.value)} placeholder="Additional notes (optional)" rows={2} className={FIELD} />
      </div>
    </>
  );

  const renderNoteFields = () => (
    <div>
      <label className={LABEL}>Content</label>
      <Textarea value={content} onChange={e => setContent(e.target.value)} placeholder="Enter your secure note..." rows={6} className={FIELD} />
    </div>
  );

  const renderCardFields = () => (
    <>
      <div>
        <label className={LABEL}>Cardholder Name</label>
        <Input value={cardholder} onChange={e => setCardholder(e.target.value)} placeholder="Name on card" className={FIELD} />
      </div>
      <div>
        <label className={LABEL}>Card Number</label>
        <Input value={cardNumber} onChange={e => setCardNumber(e.target.value)} placeholder="Card number" className={`${FIELD} font-mono`} />
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className={LABEL}>Expiry</label>
          <Input value={expiry} onChange={e => setExpiry(e.target.value)} placeholder="MM/YY" className={FIELD} />
        </div>
        <div>
          <label className={LABEL}>CVV</label>
          <Input type="password" value={cvv} onChange={e => setCvv(e.target.value)} placeholder="CVV" className={`${FIELD} font-mono`} />
        </div>
      </div>
      <div>
        <label className={LABEL}>Notes</label>
        <Textarea value={cardNotes} onChange={e => setCardNotes(e.target.value)} placeholder="Additional notes (optional)" rows={2} className={FIELD} />
      </div>
    </>
  );

  const renderCustomFields = () => (
    <>
      {customFields.map((cf, i) => (
        <div key={i} className="flex items-start gap-2">
          <div className="flex-1">
            <Input value={cf.key} onChange={e => updateCustomField(i, 'key', e.target.value)} placeholder="Field name" className={FIELD} />
          </div>
          <div className="flex-1">
            <Input value={cf.value} onChange={e => updateCustomField(i, 'value', e.target.value)} placeholder="Value" className={FIELD} />
          </div>
          {customFields.length > 1 && (
            <Button variant="ghost" size="icon" onClick={() => removeCustomField(i)} className="h-9 w-9 shrink-0">
              <X className="h-4 w-4" />
            </Button>
          )}
        </div>
      ))}
      <Button variant="outline" size="sm" onClick={addCustomField} className="w-full">
        <Plus className="h-4 w-4 mr-1" />
        Add Field
      </Button>
    </>
  );

  const renderTypeFields = () => {
    switch (type) {
      case 'login': return renderLoginFields();
      case 'note': return renderNoteFields();
      case 'card': return renderCardFields();
      case 'custom': return renderCustomFields();
    }
  };

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Edit {typeLabel(type)}</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div>
            <label className={LABEL}>Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Item name" className={FIELD} />
          </div>
          {renderTypeFields()}
          <Button className="w-full" onClick={handleSave} disabled={saving || !canSave()}>
            {saving ? 'Saving...' : 'Save Changes'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
