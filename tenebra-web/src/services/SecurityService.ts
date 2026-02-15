/**
 * SecurityService — Local encryption layer for Tenebra Web.
 *
 * Uses the Web Crypto API exclusively:
 *   • PBKDF2  (SHA-256, 100 000 iterations) to derive a CryptoKey from a password + salt.
 *   • AES-GCM (256-bit) to encrypt / decrypt arbitrary UTF-8 strings.
 *
 * All outputs are Base64-encoded for safe storage in IndexedDB.
 */

const PBKDF2_ITERATIONS = 100_000;
const PBKDF2_HASH = 'SHA-256';
const AES_ALGORITHM = 'AES-GCM';
const AES_KEY_LENGTH = 256;
const IV_BYTE_LENGTH = 12; // 96-bit IV recommended for AES-GCM

// ─── Helpers ───────────────────────────────────────────────────────────────────

function arrayBufferToBase64(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let binary = '';
  for (let i = 0; i < bytes.byteLength; i++) {
    binary += String.fromCharCode(bytes[i]);
  }
  return btoa(binary);
}

function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes.buffer;
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a cryptographically secure random salt (Base64 string).
 * @param byteLength Number of random bytes (default 16 = 128-bit).
 */
export function generateSalt(byteLength = 16): string {
  const bytes = crypto.getRandomValues(new Uint8Array(byteLength));
  return arrayBufferToBase64(bytes.buffer);
}

/**
 * Derive an AES-GCM CryptoKey from a user-supplied password and salt using PBKDF2.
 */
export async function deriveKey(password: string, salt: string): Promise<CryptoKey> {
  const encoder = new TextEncoder();

  const keyMaterial = await crypto.subtle.importKey(
    'raw',
    encoder.encode(password),
    'PBKDF2',
    false,
    ['deriveKey']
  );

  return crypto.subtle.deriveKey(
    {
      name: 'PBKDF2',
      salt: base64ToArrayBuffer(salt),
      iterations: PBKDF2_ITERATIONS,
      hash: PBKDF2_HASH,
    },
    keyMaterial,
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    false, // non-extractable
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a UTF-8 string with AES-GCM.
 * @returns An object with Base64-encoded `cipherText` and `iv`.
 */
export async function encrypt(
  data: string,
  key: CryptoKey
): Promise<{ cipherText: string; iv: string }> {
  const encoder = new TextEncoder();
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));

  const encrypted = await crypto.subtle.encrypt(
    { name: AES_ALGORITHM, iv },
    key,
    encoder.encode(data)
  );

  return {
    cipherText: arrayBufferToBase64(encrypted),
    iv: arrayBufferToBase64(iv.buffer),
  };
}

/**
 * Decrypt a Base64-encoded AES-GCM cipherText back to the original UTF-8 string.
 */
export async function decrypt(
  cipherText: string,
  iv: string,
  key: CryptoKey
): Promise<string> {
  const decrypted = await crypto.subtle.decrypt(
    { name: AES_ALGORITHM, iv: base64ToArrayBuffer(iv) },
    key,
    base64ToArrayBuffer(cipherText)
  );

  return new TextDecoder().decode(decrypted);
}
