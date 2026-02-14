import { useState } from 'react';
import { useVault } from '@/contexts/VaultContext';
import { ItemType } from '@/types/vault';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { Textarea } from '@/components/ui/textarea';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Popover, PopoverContent, PopoverTrigger } from '@/components/ui/popover';
import PasswordGenerator from '@/components/PasswordGenerator';
import { useToast } from '@/hooks/use-toast';
import { Eye, EyeOff, Plus, Wand2, X } from 'lucide-react';

interface AddItemDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
}

interface CustomField {
  key: string;
  value: string;
}

const LABEL = 'text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block';
const FIELD = 'bg-muted border-border';

export default function AddItemDialog({ open, onOpenChange, vaultId }: AddItemDialogProps) {
  const { addItem } = useVault();
  const { toast } = useToast();

  const [name, setName] = useState('');
  const [type, setType] = useState<ItemType>('login');
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

  const resetForm = () => {
    setName('');
    setType('login');
    setShowPassword(false);
    setShowGenerator(false);
    setUsername('');
    setPassword('');
    setUrl('');
    setTotp('');
    setNotes('');
    setContent('');
    setCardholder('');
    setCardNumber('');
    setExpiry('');
    setCvv('');
    setCardNotes('');
    setCustomFields([{ key: '', value: '' }]);
  };

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

  const handleAdd = async () => {
    if (!canSave()) return;
    setSaving(true);
    try {
      await addItem(vaultId, name.trim(), type, buildFields());
      resetForm();
      onOpenChange(false);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to add item.';
      toast({ title: 'Add item failed', description: msg, variant: 'destructive' });
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
                <Button
                  type="button"
                  variant="ghost"
                  size="icon"
                  className="h-full w-10"
                  title="Generate password"
                >
                  <Wand2 className="h-4 w-4" />
                </Button>
              </PopoverTrigger>
              <PopoverContent className="w-80 p-4 bg-card border-border" align="end" side="bottom">
                <PasswordGenerator onUse={(value) => { setPassword(value); setShowPassword(true); setShowGenerator(false); }} />
              </PopoverContent>
            </Popover>
            <Button
              type="button"
              variant="ghost"
              size="icon"
              className="h-full w-10"
              onClick={() => setShowPassword(!showPassword)}
            >
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
          <DialogTitle>Add Item</DialogTitle>
        </DialogHeader>
        <div className="space-y-4 mt-2">
          <div>
            <label className={LABEL}>Name</label>
            <Input value={name} onChange={e => setName(e.target.value)} placeholder="Item name" className={FIELD} />
          </div>
          <div>
            <label className={LABEL}>Type</label>
            <Select value={type} onValueChange={(v: ItemType) => setType(v)}>
              <SelectTrigger className={FIELD}>
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-popover border-border">
                <SelectItem value="login">Login</SelectItem>
                <SelectItem value="note">Secure Note</SelectItem>
                <SelectItem value="card">Card</SelectItem>
                <SelectItem value="custom">Custom</SelectItem>
              </SelectContent>
            </Select>
          </div>
          {renderTypeFields()}
          <Button className="w-full" onClick={handleAdd} disabled={saving || !canSave()}>
            {saving ? 'Adding...' : 'Add Item'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
