/**
 * FileCryptoService — Client-side file encryption for Tenebra Web.
 *
 * Encrypts files with a random AES-GCM-256 key before upload so the
 * server (MinIO) only ever stores opaque ciphertext.  The file key and
 * IV travel inside the E2EE message payload, never in plaintext.
 *
 * Key lifecycle:
 *   1. `generateFileKey()`   → random extractable AES-GCM-256 CryptoKey
 *   2. `encryptFile(file, key)` → encrypted ArrayBuffer + IV
 *   3. `exportKey(key)`      → raw Base64 for inclusion in the message
 *   4. Recipient: `importKey(b64)` → CryptoKey
 *   5. `decryptFile(blob, key, iv)` → decrypted Blob
 */

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

function base64ToUint8Array(base64: string): Uint8Array {
  const binary = atob(base64);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a random AES-GCM-256 key for encrypting a single file.
 * The key is **extractable** so it can be serialised for the wire.
 */
export async function generateFileKey(): Promise<CryptoKey> {
  return crypto.subtle.generateKey(
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    true, // extractable — we need to export it for the message payload
    ['encrypt', 'decrypt']
  );
}

/**
 * Encrypt a `File` (or `Blob`) with AES-GCM.
 *
 * @returns The encrypted data as an `ArrayBuffer` and the random IV.
 */
export async function encryptFile(
  file: File | Blob,
  key: CryptoKey
): Promise<{ encrypted: ArrayBuffer; iv: Uint8Array }> {
  const iv = crypto.getRandomValues(new Uint8Array(IV_BYTE_LENGTH));
  const plaintext = await file.arrayBuffer();

  const encrypted = await crypto.subtle.encrypt({ name: AES_ALGORITHM, iv }, key, plaintext);

  return { encrypted, iv };
}

/**
 * Decrypt an encrypted blob back to the original file content.
 */
export async function decryptFile(
  encryptedBlob: Blob,
  key: CryptoKey,
  iv: Uint8Array
): Promise<Blob> {
  const ciphertext = await encryptedBlob.arrayBuffer();

  const decrypted = await crypto.subtle.decrypt(
    { name: AES_ALGORITHM, iv: iv as BufferSource },
    key,
    ciphertext
  );

  return new Blob([decrypted]);
}

/**
 * Export a CryptoKey to a raw Base64 string for inclusion in a message payload.
 */
export async function exportKeyToBase64(key: CryptoKey): Promise<string> {
  const raw = await crypto.subtle.exportKey('raw', key);
  return arrayBufferToBase64(raw);
}

/**
 * Import a raw Base64 key back into a CryptoKey for decryption.
 */
export async function importKeyFromBase64(base64: string): Promise<CryptoKey> {
  const raw = base64ToUint8Array(base64);
  return crypto.subtle.importKey(
    'raw',
    raw as BufferSource,
    { name: AES_ALGORITHM, length: AES_KEY_LENGTH },
    false, // non-extractable — only needed for decryption
    ['decrypt']
  );
}

/**
 * Encode a Uint8Array IV to a Base64 string.
 */
export function ivToBase64(iv: Uint8Array): string {
  return arrayBufferToBase64(iv.buffer as ArrayBuffer);
}

/**
 * Decode a Base64 string back to a Uint8Array IV.
 */
export function ivFromBase64(base64: string): Uint8Array {
  return base64ToUint8Array(base64);
}
