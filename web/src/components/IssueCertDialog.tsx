import { useState } from 'react';
import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import { Button } from '@/components/ui/button';
import { Input } from '@/components/ui/input';
import { useToast } from '@/hooks/use-toast';
import { issueCert } from '@/lib/api';

interface IssueCertDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  vaultId: string;
  onSuccess: () => void;
}

const LABEL = 'text-xs font-medium text-muted-foreground uppercase tracking-wider mb-2 block';
const FIELD = 'bg-muted border-border';

const EXT_KEY_USAGE_OPTIONS = [
  { value: 'server_auth', label: 'Server Auth (TLS)' },
  { value: 'client_auth', label: 'Client Auth' },
  { value: 'code_signing', label: 'Code Signing' },
  { value: 'email_protection', label: 'Email Protection' },
];

export default function IssueCertDialog({ open, onOpenChange, vaultId, onSuccess }: IssueCertDialogProps) {
  const { toast } = useToast();
  const [commonName, setCommonName] = useState('');
  const [organization, setOrganization] = useState('');
  const [orgUnit, setOrgUnit] = useState('');
  const [country, setCountry] = useState('');
  const [validityDays, setValidityDays] = useState('365');
  const [dnsNames, setDnsNames] = useState('');
  const [ipAddresses, setIpAddresses] = useState('');
  const [emailAddresses, setEmailAddresses] = useState('');
  const [extKeyUsages, setExtKeyUsages] = useState<Set<string>>(new Set(['server_auth']));
  const [saving, setSaving] = useState(false);

  const canSave = commonName.trim().length > 0;

  const resetForm = () => {
    setCommonName('');
    setOrganization('');
    setOrgUnit('');
    setCountry('');
    setValidityDays('365');
    setDnsNames('');
    setIpAddresses('');
    setEmailAddresses('');
    setExtKeyUsages(new Set(['server_auth']));
  };

  const toggleUsage = (usage: string) => {
    setExtKeyUsages(prev => {
      const next = new Set(prev);
      if (next.has(usage)) {
        next.delete(usage);
      } else {
        next.add(usage);
      }
      return next;
    });
  };

  const splitCSV = (s: string): string[] =>
    s.split(',').map(v => v.trim()).filter(Boolean);

  const handleIssue = async () => {
    if (!canSave) return;
    setSaving(true);
    try {
      const result = await issueCert(vaultId, {
        common_name: commonName.trim(),
        organization: organization.trim() || undefined,
        org_unit: orgUnit.trim() || undefined,
        country: country.trim() || undefined,
        validity_days: parseInt(validityDays) || 365,
        ext_key_usages: Array.from(extKeyUsages),
        dns_names: splitCSV(dnsNames).length > 0 ? splitCSV(dnsNames) : undefined,
        ip_addresses: splitCSV(ipAddresses).length > 0 ? splitCSV(ipAddresses) : undefined,
        email_addresses: splitCSV(emailAddresses).length > 0 ? splitCSV(emailAddresses) : undefined,
      });
      toast({
        title: 'Certificate issued',
        description: `Serial: ${result.serial_number}`,
      });
      resetForm();
      onOpenChange(false);
      onSuccess();
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to issue certificate.';
      toast({ title: 'Issue failed', description: msg, variant: 'destructive' });
    } finally {
      setSaving(false);
    }
  };

  return (
    <Dialog open={open} onOpenChange={(o) => { onOpenChange(o); if (!o) resetForm(); }}>
      <DialogContent className="bg-card border-border max-h-[85vh] overflow-y-auto">
        <DialogHeader>
          <DialogTitle>Issue Certificate</DialogTitle>
        </DialogHeader>
        <p className="text-sm text-muted-foreground">
          Issue a new X.509 certificate signed by this vault's CA. An ECDSA P-256 key pair will be generated automatically.
        </p>
        <div className="space-y-3 mt-2">
          <div>
            <label className={LABEL}>Common Name *</label>
            <Input value={commonName} onChange={e => setCommonName(e.target.value)} placeholder="app.example.com" className={FIELD} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>Organization</label>
              <Input value={organization} onChange={e => setOrganization(e.target.value)} placeholder="Acme Corp" className={FIELD} />
            </div>
            <div>
              <label className={LABEL}>Country</label>
              <Input value={country} onChange={e => setCountry(e.target.value)} placeholder="US" maxLength={2} className={FIELD} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className={LABEL}>Org Unit</label>
              <Input value={orgUnit} onChange={e => setOrgUnit(e.target.value)} placeholder="Engineering" className={FIELD} />
            </div>
            <div>
              <label className={LABEL}>Validity (days)</label>
              <Input
                type="number"
                value={validityDays}
                onChange={e => setValidityDays(e.target.value)}
                min={1}
                max={3650}
                className={FIELD}
              />
            </div>
          </div>
          <div>
            <label className={LABEL}>DNS Names (comma-separated)</label>
            <Input
              value={dnsNames}
              onChange={e => setDnsNames(e.target.value)}
              placeholder="app.example.com, *.example.com"
              className={FIELD}
            />
          </div>
          <div>
            <label className={LABEL}>IP Addresses (comma-separated)</label>
            <Input
              value={ipAddresses}
              onChange={e => setIpAddresses(e.target.value)}
              placeholder="10.0.0.1, 192.168.1.1"
              className={FIELD}
            />
          </div>
          <div>
            <label className={LABEL}>Email Addresses (comma-separated)</label>
            <Input
              value={emailAddresses}
              onChange={e => setEmailAddresses(e.target.value)}
              placeholder="admin@example.com"
              className={FIELD}
            />
          </div>
          <div>
            <label className={LABEL}>Extended Key Usage</label>
            <div className="flex flex-wrap gap-2">
              {EXT_KEY_USAGE_OPTIONS.map(opt => (
                <label key={opt.value} className="flex items-center gap-1.5 text-sm cursor-pointer">
                  <input
                    type="checkbox"
                    checked={extKeyUsages.has(opt.value)}
                    onChange={() => toggleUsage(opt.value)}
                    className="rounded border-border"
                  />
                  {opt.label}
                </label>
              ))}
            </div>
          </div>
          <Button className="w-full" onClick={handleIssue} disabled={saving || !canSave}>
            {saving ? 'Issuing...' : 'Issue Certificate'}
          </Button>
        </div>
      </DialogContent>
    </Dialog>
  );
}
