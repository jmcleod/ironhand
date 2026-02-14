import words from './wordlist';

// Cryptographically secure random integer in [0, max).
function secureRandomInt(max: number): number {
  const array = new Uint32Array(1);
  crypto.getRandomValues(array);
  return array[0] % max;
}

// --- Random Password ---

export interface RandomPasswordOptions {
  length: number;       // 8–100
  includeNumbers: boolean;
  includeSymbols: boolean;
}

export function generateRandomPassword(opts: RandomPasswordOptions): string {
  const lower = 'abcdefghijklmnopqrstuvwxyz';
  const upper = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
  const digits = '0123456789';
  const symbols = '!@#$%^&*()-_=+[]{}|;:,.<>?';

  let charset = lower + upper;
  const required: string[] = [
    lower[secureRandomInt(lower.length)],
    upper[secureRandomInt(upper.length)],
  ];

  if (opts.includeNumbers) {
    charset += digits;
    required.push(digits[secureRandomInt(digits.length)]);
  }
  if (opts.includeSymbols) {
    charset += symbols;
    required.push(symbols[secureRandomInt(symbols.length)]);
  }

  const result: string[] = [...required];
  for (let i = result.length; i < opts.length; i++) {
    result.push(charset[secureRandomInt(charset.length)]);
  }

  // Fisher-Yates shuffle to avoid guaranteed positions.
  for (let i = result.length - 1; i > 0; i--) {
    const j = secureRandomInt(i + 1);
    [result[i], result[j]] = [result[j], result[i]];
  }

  return result.join('');
}

// --- Memorable Password ---

export type Separator = ' ' | '-' | '.' | ',' | '_';

export interface MemorablePasswordOptions {
  wordCount: number;    // 3–15
  separator: Separator;
  capitalize: boolean;
}

export function generateMemorablePassword(opts: MemorablePasswordOptions): string {
  const selected: string[] = [];
  for (let i = 0; i < opts.wordCount; i++) {
    const word = words[secureRandomInt(words.length)];
    selected.push(opts.capitalize ? word.charAt(0).toUpperCase() + word.slice(1) : word);
  }
  return selected.join(opts.separator);
}

// --- PIN Code ---

export interface PinCodeOptions {
  length: number;       // 3–12
}

export function generatePinCode(opts: PinCodeOptions): string {
  const digits: string[] = [];
  for (let i = 0; i < opts.length; i++) {
    digits.push(String(secureRandomInt(10)));
  }
  return digits.join('');
}
