import { useCallback, useEffect, useRef, useState } from 'react';
import { generateTOTP, totpSecondsRemaining, totpPeriod, isValidTOTPSecret } from '@/lib/totp';
import { Button } from '@/components/ui/button';
import { Copy, Check, AlertCircle } from 'lucide-react';

interface TotpCodeDisplayProps {
  secret: string;
}

export default function TotpCodeDisplay({ secret }: TotpCodeDisplayProps) {
  const [code, setCode] = useState<string | null>(null);
  const [remaining, setRemaining] = useState(totpSecondsRemaining());
  const [copied, setCopied] = useState(false);
  const [error, setError] = useState(false);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);
  const period = totpPeriod();

  const refreshCode = useCallback(async () => {
    if (!isValidTOTPSecret(secret)) {
      setError(true);
      setCode(null);
      return;
    }
    try {
      const newCode = await generateTOTP(secret);
      setCode(newCode);
      setError(false);
    } catch {
      setError(true);
      setCode(null);
    }
  }, [secret]);

  useEffect(() => {
    // Generate code immediately
    refreshCode();

    // Tick every second for countdown + code refresh at period boundary
    intervalRef.current = setInterval(() => {
      const secs = totpSecondsRemaining();
      setRemaining(secs);

      // When we cross the period boundary, regenerate the code
      if (secs === period) {
        refreshCode();
      }
    }, 1000);

    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current);
    };
  }, [refreshCode, period]);

  const handleCopy = () => {
    if (!code) return;
    navigator.clipboard.writeText(code);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  if (error) {
    return (
      <div className="flex items-center gap-2">
        <AlertCircle className="h-4 w-4 text-destructive shrink-0" />
        <span className="text-xs text-destructive">Invalid TOTP secret</span>
      </div>
    );
  }

  if (!code) {
    return <span className="text-sm text-muted-foreground">Generating...</span>;
  }

  // Split code into two halves for readability (e.g., "123 456")
  const formatted = code.slice(0, 3) + ' ' + code.slice(3);

  // Countdown progress: full at 30s, empty at 0s
  const progressPercent = (remaining / period) * 100;
  const isUrgent = remaining <= 5;

  return (
    <div className="flex items-center gap-2">
      <span className={`font-mono text-lg font-semibold tracking-widest ${isUrgent ? 'text-destructive' : 'text-foreground'}`}>
        {formatted}
      </span>

      {/* Circular countdown */}
      <div className="relative h-6 w-6 shrink-0" title={`${remaining}s remaining`}>
        <svg className="h-6 w-6 -rotate-90" viewBox="0 0 24 24">
          <circle
            cx="12"
            cy="12"
            r="10"
            fill="none"
            strokeWidth="2"
            className="stroke-muted"
          />
          <circle
            cx="12"
            cy="12"
            r="10"
            fill="none"
            strokeWidth="2"
            strokeDasharray={`${2 * Math.PI * 10}`}
            strokeDashoffset={`${2 * Math.PI * 10 * (1 - progressPercent / 100)}`}
            strokeLinecap="round"
            className={isUrgent ? 'stroke-destructive' : 'stroke-primary'}
            style={{ transition: 'stroke-dashoffset 1s linear' }}
          />
        </svg>
        <span className={`absolute inset-0 flex items-center justify-center text-[9px] font-medium ${isUrgent ? 'text-destructive' : 'text-muted-foreground'}`}>
          {remaining}
        </span>
      </div>

      <Button
        variant="ghost"
        size="icon"
        onClick={handleCopy}
        className="h-7 w-7 shrink-0"
        title="Copy code"
      >
        {copied ? (
          <Check className="h-3.5 w-3.5 text-green-500" />
        ) : (
          <Copy className="h-3.5 w-3.5" />
        )}
      </Button>
    </div>
  );
}
