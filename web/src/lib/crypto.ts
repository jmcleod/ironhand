export function generateAccountKey(): string {
  const chars = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  const segments = 4;
  const segmentLength = 5;
  const parts: string[] = [];
  
  for (let s = 0; s < segments; s++) {
    let segment = '';
    for (let i = 0; i < segmentLength; i++) {
      const randomIndex = Math.floor(Math.random() * chars.length);
      segment += chars[randomIndex];
    }
    parts.push(segment);
  }
  
  return parts.join('-');
}

export function generateId(): string {
  return crypto.randomUUID?.() ?? Math.random().toString(36).substring(2) + Date.now().toString(36);
}

// Simple hash for demo purposes - in production use proper crypto
export async function hashPassphrase(passphrase: string): Promise<string> {
  const encoder = new TextEncoder();
  const data = encoder.encode(passphrase);
  const hashBuffer = await crypto.subtle.digest('SHA-256', data);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

// Simple XOR-based obfuscation for demo - in production use AES-GCM
export function encryptData(data: string, key: string): string {
  return btoa(
    data
      .split('')
      .map((char, i) => String.fromCharCode(char.charCodeAt(0) ^ key.charCodeAt(i % key.length)))
      .join('')
  );
}

export function decryptData(encrypted: string, key: string): string {
  const decoded = atob(encrypted);
  return decoded
    .split('')
    .map((char, i) => String.fromCharCode(char.charCodeAt(0) ^ key.charCodeAt(i % key.length)))
    .join('');
}
