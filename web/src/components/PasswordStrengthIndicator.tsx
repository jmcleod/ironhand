import { assessPasswordStrength } from '@/lib/password-strength';
import { cn } from '@/lib/utils';

interface PasswordStrengthIndicatorProps {
  password: string;
  showGuidance?: boolean;
  className?: string;
}

export default function PasswordStrengthIndicator({
  password,
  showGuidance = true,
  className,
}: PasswordStrengthIndicatorProps) {
  const strength = assessPasswordStrength(password);
  const widths = ['w-1/5', 'w-2/5', 'w-3/5', 'w-4/5', 'w-full'];
  const colors = [
    'bg-red-500',
    'bg-orange-500',
    'bg-amber-500',
    'bg-lime-500',
    'bg-green-500',
  ];

  return (
    <div className={cn('mt-2 space-y-1.5', className)}>
      <div className="h-1.5 w-full rounded-full bg-muted overflow-hidden">
        <div className={`h-full ${widths[strength.score]} ${colors[strength.score]} transition-all`} />
      </div>
      <p className="text-xs text-muted-foreground">
        Strength: <span className="font-medium">{strength.label}</span>
      </p>
      {showGuidance && strength.isWeak && (
        <p className="text-xs text-amber-600 dark:text-amber-400">
          Weak password. Use at least 12 characters with uppercase, lowercase, numbers, and symbols.
        </p>
      )}
    </div>
  );
}
