export type PasswordStrengthLevel = 'very-weak' | 'weak' | 'fair' | 'good' | 'strong';

export interface PasswordStrength {
  score: number; // 0-4
  level: PasswordStrengthLevel;
  label: string;
  isWeak: boolean;
}

const commonPasswords = new Set([
  'password',
  'password123',
  '123456',
  '12345678',
  'qwerty',
  'abc123',
  'letmein',
  'admin',
  'welcome',
  'iloveyou',
]);

export function assessPasswordStrength(password: string): PasswordStrength {
  if (!password) {
    return { score: 0, level: 'very-weak', label: 'Very weak', isWeak: true };
  }

  const trimmed = password.trim();
  const lower = trimmed.toLowerCase();

  let score = 0;

  if (trimmed.length >= 8) score++;
  if (trimmed.length >= 12) score++;
  if (/[a-z]/.test(trimmed) && /[A-Z]/.test(trimmed)) score++;
  if (/\d/.test(trimmed)) score++;
  if (/[^a-zA-Z0-9]/.test(trimmed)) score++;

  if (commonPasswords.has(lower)) {
    score = 0;
  }
  if (/^(.)\1+$/.test(trimmed) || /^(1234|abcd|qwer)/i.test(trimmed)) {
    score = Math.min(score, 1);
  }

  score = Math.max(0, Math.min(4, score));

  if (score <= 1) {
    return { score, level: score === 0 ? 'very-weak' : 'weak', label: score === 0 ? 'Very weak' : 'Weak', isWeak: true };
  }
  if (score === 2) {
    return { score, level: 'fair', label: 'Fair', isWeak: false };
  }
  if (score === 3) {
    return { score, level: 'good', label: 'Good', isWeak: false };
  }
  return { score, level: 'strong', label: 'Strong', isWeak: false };
}
