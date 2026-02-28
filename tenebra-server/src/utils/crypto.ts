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
  } catch (error) {
    // Treat common input-related errors as verification failures
    if (error instanceof Error && (error.name === 'TypeError' || error.name === 'RangeError')) {
      return false;
    }
    // Log and rethrow truly unexpected errors
    console.error('verifySignature: unexpected error during signature verification', error);
    throw error;
  }
}

/**
 * Generate a cryptographically secure random nonce.
 *
 * Always produces a 32-byte (64-character hex) nonce that fits the
 * auth_challenges.nonce VARCHAR(64) column.
 *
 * @returns Hex-encoded nonce string (64 characters)
 */
export function generateNonce(): string {
  return crypto.randomBytes(32).toString('hex');
}
