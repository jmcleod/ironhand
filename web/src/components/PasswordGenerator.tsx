import { useCallback, useEffect, useState } from 'react';
import { Tabs, TabsContent, TabsList, TabsTrigger } from '@/components/ui/tabs';
import { Button } from '@/components/ui/button';
import { Slider } from '@/components/ui/slider';
import { Switch } from '@/components/ui/switch';
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from '@/components/ui/select';
import { Copy, Check, RefreshCw } from 'lucide-react';
import {
  generateRandomPassword,
  generateMemorablePassword,
  generatePinCode,
  type Separator,
} from '@/lib/password-generator';

interface PasswordGeneratorProps {
  /** When provided, shows a "Use" button that passes the generated value back. */
  onUse?: (value: string) => void;
}

const LABEL = 'text-xs font-medium text-muted-foreground uppercase tracking-wider';

type GeneratorTab = 'random' | 'memorable' | 'pin';

const SEPARATORS: Separator[] = [' ', '-', '.', ',', '_'];

function separatorLabel(s: Separator) {
  switch (s) {
    case ' ': return 'Spaces';
    case '-': return 'Hyphens';
    case '.': return 'Periods';
    case ',': return 'Commas';
    case '_': return 'Underscores';
  }
}

export default function PasswordGenerator({ onUse }: PasswordGeneratorProps) {
  const [tab, setTab] = useState<GeneratorTab>('random');
  const [output, setOutput] = useState('');
  const [copied, setCopied] = useState(false);

  // Random options
  const [length, setLength] = useState(20);
  const [includeNumbers, setIncludeNumbers] = useState(true);
  const [includeSymbols, setIncludeSymbols] = useState(true);

  // Memorable options
  const [wordCount, setWordCount] = useState(5);
  const [separator, setSeparator] = useState<Separator>('-');
  const [capitalize, setCapitalize] = useState(true);

  // PIN options
  const [pinLength, setPinLength] = useState(6);

  const generate = useCallback(() => {
    setCopied(false);
    switch (tab) {
      case 'random':
        setOutput(generateRandomPassword({ length, includeNumbers, includeSymbols }));
        break;
      case 'memorable':
        setOutput(generateMemorablePassword({ wordCount, separator, capitalize }));
        break;
      case 'pin':
        setOutput(generatePinCode({ length: pinLength }));
        break;
    }
  }, [tab, length, includeNumbers, includeSymbols, wordCount, separator, capitalize, pinLength]);

  // Auto-generate on option change.
  useEffect(() => {
    generate();
  }, [generate]);

  const handleCopy = () => {
    navigator.clipboard.writeText(output);
    setCopied(true);
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <div className="space-y-3">
      {/* Output display */}
      <div className="flex items-center gap-2 p-3 rounded-xl bg-muted border border-border min-h-[44px]">
        <code className="font-mono text-sm text-primary break-all flex-1 select-all leading-snug">{output}</code>
        <div className="flex items-center gap-0.5 shrink-0">
          <Button variant="ghost" size="icon" onClick={generate} className="h-7 w-7" title="Regenerate">
            <RefreshCw className="h-3.5 w-3.5" />
          </Button>
          <Button variant="ghost" size="icon" onClick={handleCopy} className="h-7 w-7" title="Copy">
            {copied ? <Check className="h-3.5 w-3.5 text-green-500" /> : <Copy className="h-3.5 w-3.5" />}
          </Button>
        </div>
      </div>

      <Tabs value={tab} onValueChange={(v) => setTab(v as GeneratorTab)}>
        <TabsList className="w-full">
          <TabsTrigger value="random" className="flex-1">Random</TabsTrigger>
          <TabsTrigger value="memorable" className="flex-1">Memorable</TabsTrigger>
          <TabsTrigger value="pin" className="flex-1">PIN</TabsTrigger>
        </TabsList>

        {/* Random Password */}
        <TabsContent value="random" className="space-y-3 mt-3">
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className={LABEL}>Length</label>
              <span className="text-sm font-mono text-foreground">{length}</span>
            </div>
            <Slider
              value={[length]}
              onValueChange={([v]) => setLength(v)}
              min={8}
              max={100}
              step={1}
            />
          </div>
          <div className="flex items-center justify-between">
            <label className={LABEL}>Include Numbers</label>
            <Switch checked={includeNumbers} onCheckedChange={setIncludeNumbers} />
          </div>
          <div className="flex items-center justify-between">
            <label className={LABEL}>Include Symbols</label>
            <Switch checked={includeSymbols} onCheckedChange={setIncludeSymbols} />
          </div>
        </TabsContent>

        {/* Memorable Password */}
        <TabsContent value="memorable" className="space-y-3 mt-3">
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className={LABEL}>Words</label>
              <span className="text-sm font-mono text-foreground">{wordCount}</span>
            </div>
            <Slider
              value={[wordCount]}
              onValueChange={([v]) => setWordCount(v)}
              min={3}
              max={15}
              step={1}
            />
          </div>
          <div className="flex items-center justify-between">
            <label className={LABEL}>Separator</label>
            <Select value={separator} onValueChange={(v) => setSeparator(v as Separator)}>
              <SelectTrigger className="w-[140px] bg-muted border-border">
                <SelectValue />
              </SelectTrigger>
              <SelectContent className="bg-popover border-border">
                {SEPARATORS.map((s) => (
                  <SelectItem key={s} value={s}>{separatorLabel(s)}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
          <div className="flex items-center justify-between">
            <label className={LABEL}>Capitalize</label>
            <Switch checked={capitalize} onCheckedChange={setCapitalize} />
          </div>
        </TabsContent>

        {/* PIN Code */}
        <TabsContent value="pin" className="space-y-3 mt-3">
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className={LABEL}>Digits</label>
              <span className="text-sm font-mono text-foreground">{pinLength}</span>
            </div>
            <Slider
              value={[pinLength]}
              onValueChange={([v]) => setPinLength(v)}
              min={3}
              max={12}
              step={1}
            />
          </div>
        </TabsContent>
      </Tabs>

      {onUse && (
        <Button className="w-full" size="sm" onClick={() => onUse(output)}>
          Use Password
        </Button>
      )}
    </div>
  );
}
