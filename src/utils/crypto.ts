import nacl from 'tweetnacl';
import { decodeBase64 } from 'tweetnacl-util';
import crypto from 'crypto';

/**
 * Verify an Ed25519 signature.
 *
 * The identity_public_key stored in the users table is expected to be
 * a base64-encoded 32-byte Ed25519 public key.
 *
 * @param publicKeyBase64 - Base64-encoded Ed25519 public key
 * @param data - The data that was signed (UTF-8 string)
 * @param signatureBase64 - Base64-encoded Ed25519 signature
 * @returns true if the signature is valid
 */
export function verifySignature(
  publicKeyBase64: string,
  data: string,
  signatureBase64: string
): boolean {
  try {
    const publicKey = decodeBase64(publicKeyBase64);
    const signature = decodeBase64(signatureBase64);
    const message = new TextEncoder().encode(data);

    return nacl.sign.detached.verify(message, signature, publicKey);
  } catch {
    return false;
  }
}

/**
 * Generate a cryptographically secure random nonce.
 *
 * @param bytes - Number of random bytes (default 32)
 * @returns Hex-encoded nonce string
 */
export function generateNonce(bytes = 32): string {
  return crypto.randomBytes(bytes).toString('hex');
}
