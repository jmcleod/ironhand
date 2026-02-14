import { Dialog, DialogContent, DialogHeader, DialogTitle } from '@/components/ui/dialog';
import PasswordGenerator from '@/components/PasswordGenerator';

interface PasswordGeneratorDialogProps {
  open: boolean;
  onOpenChange: (open: boolean) => void;
}

export default function PasswordGeneratorDialog({ open, onOpenChange }: PasswordGeneratorDialogProps) {
  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="bg-card border-border sm:max-w-md">
        <DialogHeader>
          <DialogTitle>Password Generator</DialogTitle>
        </DialogHeader>
        <PasswordGenerator />
      </DialogContent>
    </Dialog>
  );
}
