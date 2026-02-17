import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { initCA } from '@/lib/api';

interface InitCADialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  onSuccess: () => void;
}

const LABEL = 'text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block';
const FIELD = 'bg-muted border-border';

export default function InitCADialog({ open, onOpenChange, vaultId, onSuccess }: InitCADialogProps) {
  const { toast } = useToast();
  const [commonName, setCommonName] = useState('');
  const [organization, setOrganization] = useState('');
  const [orgUnit, setOrgUnit] = useState('');
  const [country, setCountry] = useState('');
  const [province, setProvince] = useState('');
  const [locality, setLocality] = useState('');
  const [validityYears, setValidityYears] = useState('10');
  const [isIntermediate, setIsIntermediate] = useState(false);
  const [saving, setSaving] = useState(false);

  const canSave = commonName.trim().length > 0;

  const resetForm = () => {
    setCommonName('');
    setOrganization('');
    setOrgUnit('');
    setCountry('');
    setProvince('');
    setLocality('');
    setValidityYears('10');
    setIsIntermediate(false);
  };

  const handleInit = async () => {
    if (!canSave) return;
    setSaving(true);
    try {
      const result = await initCA(vaultId, {
        common_name: commonName.trim(),
        organization: organization.trim() || undefined,
        org_unit: orgUnit.trim() || undefined,
        country: country.trim() || undefined,
        province: province.trim() || undefined,
        locality: locality.trim() || undefined,
        validity_years: parseInt(validityYears) || 10,
        is_intermediate: isIntermediate,
      });
      toast({ title: 'CA initialized', description: `Subject: ${result.subject}` });
      resetForm();
      onOpenChange(false);
      onSuccess();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to initialize CA.';
      toast({ title: 'CA init failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) resetForm(); }}>
      <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Initialize Certificate Authority</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Turn this vault into a Certificate Authority. A self-signed root CA certificate and ECDSA P-256 key pair will be generated.
        </p>
        <div className="space-y-3 mt-2">
          <div>
            <label className={LABEL}>Common Name *</label>
            <Input value={commonName} onChange={e => setCommonName(e.target.value)} placeholder="My Root CA" className={FIELD} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>Organization</label>
              <Input value={organization} onChange={e => setOrganization(e.target.value)} placeholder="Acme Corp" className={FIELD} />
            </div>
            <div>
              <label className={LABEL}>Org Unit</label>
              <Input value={orgUnit} onChange={e => setOrgUnit(e.target.value)} placeholder="IT Security" className={FIELD} />
            </div>
          </div>
          <div className="grid grid-cols-3 gap-3">
            <div>
              <label className={LABEL}>Country</label>
              <Input value={country} onChange={e => setCountry(e.target.value)} placeholder="US" maxLength={2} className={FIELD} />
            </div>
            <div>
              <label className={LABEL}>Province</label>
              <Input value={province} onChange={e => setProvince(e.target.value)} placeholder="California" className={FIELD} />
            </div>
            <div>
              <label className={LABEL}>Locality</label>
              <Input value={locality} onChange={e => setLocality(e.target.value)} placeholder="San Francisco" className={FIELD} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>Validity (years)</label>
              <Input
                type="number"
                value={validityYears}
                onChange={e => setValidityYears(e.target.value)}
                min={1}
                max={30}
                className={FIELD}
              />
            </div>
            <div className="flex items-end pb-1">
              <label className="flex items-center gap-2 text-sm cursor-pointer">
                <input
                  type="checkbox"
                  checked={isIntermediate}
                  onChange={e => setIsIntermediate(e.target.checked)}
                  className="rounded border-border"
                />
                Intermediate CA
              </label>
            </div>
          </div>
          <Button className="w-full" onClick={handleInit} disabled={saving || !canSave}>
            {saving ? 'Initializing...' : 'Initialize CA'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
