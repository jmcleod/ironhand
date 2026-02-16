/**
 * Client-side TOTP (RFC 6238) code generation.
 *
 * Uses the Web Crypto API (SubtleCrypto) for HMAC-SHA1 computation.
 * Compatible with the backend implementation in api/totp.go.
 */

const TOTP_PERIOD = 30; // seconds
const TOTP_DIGITS = 6;

/**
 * Decode a base32-encoded string into a Uint8Array.
 * Handles both padded and unpadded input, case-insensitive.
 */
function base32Decode(input: string): Uint8Array {
  const alphabet = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';
  const cleaned = input.toUpperCase().replace(/[=\s]/g, '');

  const out: number[] = [];
  let buffer = 0;
  let bitsLeft = 0;

  for (const ch of cleaned) {
    const val = alphabet.indexOf(ch);
    if (val === -1) {
      throw new Error(`Invalid base32 character: ${ch}`);
    }
    buffer = (buffer << 5) | val;
    bitsLeft += 5;
    if (bitsLeft >= 8) {
      bitsLeft -= 8;
      out.push((buffer >> bitsLeft) & 0xff);
    }
  }

  return new Uint8Array(out);
}

/**
 * Generate a TOTP code for the given secret at the specified time.
 *
 * @param secret - Base32-encoded TOTP secret
 * @param time - Unix timestamp in seconds (defaults to now)
 * @returns 6-digit TOTP code string
 */
export async function generateTOTP(secret: string, time?: number): Promise<string> {
  const now = time ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / TOTP_PERIOD);

  const keyData = base32Decode(secret);

  // Import HMAC-SHA1 key
  const key = await crypto.subtle.importKey(
    'raw',
    keyData,
    { name: 'HMAC', hash: 'SHA-1' },
    false,
    ['sign'],
  );

  // Encode counter as big-endian 8-byte buffer
  const msg = new ArrayBuffer(8);
  const view = new DataView(msg);
  // Use two 32-bit writes since DataView doesn't have setUint64
  view.setUint32(0, Math.floor(counter / 0x100000000));
  view.setUint32(4, counter >>> 0);

  const signature = await crypto.subtle.sign('HMAC', key, msg);
  const hash = new Uint8Array(signature);

  // Dynamic truncation (RFC 4226 §5.4)
  const offset = hash[hash.length - 1] & 0x0f;
  const binCode =
    ((hash[offset] & 0x7f) << 24) |
    ((hash[offset + 1] & 0xff) << 16) |
    ((hash[offset + 2] & 0xff) << 8) |
    (hash[offset + 3] & 0xff);

  const otp = binCode % 10 ** TOTP_DIGITS;
  return otp.toString().padStart(TOTP_DIGITS, '0');
}

/**
 * Returns the number of seconds remaining in the current TOTP period.
 */
export function totpSecondsRemaining(): number {
  const now = Math.floor(Date.now() / 1000);
  return TOTP_PERIOD - (now % TOTP_PERIOD);
}

/**
 * Returns the total TOTP period length in seconds.
 */
export function totpPeriod(): number {
  return TOTP_PERIOD;
}

/**
 * Check if a string looks like a valid base32-encoded TOTP secret.
 */
export function isValidTOTPSecret(secret: string): boolean {
  if (!secret || secret.trim().length < 8) return false;
  const cleaned = secret.toUpperCase().replace(/[=\s]/g, '');
  return /^[A-Z2-7]+$/.test(cleaned);
}
