/**
 * SignalStoreAdapter — Encrypted key-material access layer.
 *
 * Wraps the Dexie tables created in `db.ts` and transparently
 * decrypts private keys (via AES-GCM through SecurityService) so
 * callers receive raw `Uint8Array` values ready for cryptographic use.
 *
 * All **write** helpers re-encrypt before persisting.
 */

import { decodeBase64 } from 'tweetnacl-util';
import { db } from '@/db/db';
import { decrypt, encrypt } from './SecurityService';

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface IdentityKeyPair {
  /** 32-byte Ed25519 public key. */
  publicKey: Uint8Array;
  /** 64-byte Ed25519 secret key (seed ‖ publicKey). */
  secretKey: Uint8Array;
  /** 16-bit unsigned registration ID. */
  registrationId: number;
}

export interface DecryptedPreKey {
  keyId: number;
  /** 32-byte X25519 public key. */
  publicKey: Uint8Array;
  /** 32-byte X25519 secret key. */
  secretKey: Uint8Array;
}

export interface DecryptedSignedPreKey extends DecryptedPreKey {
  /** Ed25519 signature over the public key (raw bytes). */
  signature: Uint8Array;
}

export interface SessionData {
  /** 32-byte root session key derived from X3DH. */
  sessionKey: string; // Base64
  /** Base64-encoded Ed25519 identity public key of the remote peer. */
  remoteIdentityKey: string;
  /** Remote peer's Signal registration ID. */
  remoteRegistrationId: number;
  /** Current sending chain key (Base64). Advanced after every outgoing message. */
  sendChainKey: string;
  /** Current receiving chain key (Base64). Advanced after every incoming message. */
  recvChainKey: string;
  /** Number of messages sent on this session (for rotation limits). */
  sendMessageCount: number;
  /** Number of messages received on this session (for rotation limits). */
  recvMessageCount: number;
  /** Unix epoch ms when this session was created. */
  createdAt: number;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/** Decrypt a Base64-encoded private key stored in Dexie. */
async function decryptKey(
  cipherText: string,
  iv: string,
  encryptionKey: CryptoKey
): Promise<Uint8Array> {
  const b64 = await decrypt(cipherText, iv, encryptionKey);
  return decodeBase64(b64);
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Retrieve the local Ed25519 identity key pair (decrypted).
 */
export async function getIdentityKeyPair(encryptionKey: CryptoKey): Promise<IdentityKeyPair> {
  const row = await db.identity.get('self');
  if (!row) throw new Error('No local identity found.');

  const secretKey = await decryptKey(
    row.encryptedPrivateKey,
    row.encryptedPrivateKeyIv,
    encryptionKey
  );

  return {
    publicKey: decodeBase64(row.publicKey),
    secretKey,
    registrationId: row.registrationId,
  };
}

/**
 * Load a signed pre-key by ID (decrypted).
 */
export async function getSignedPreKey(
  keyId: number,
  encryptionKey: CryptoKey
): Promise<DecryptedSignedPreKey> {
  const row = await db.signedPreKeys.get(keyId);
  if (!row) throw new Error(`Signed pre-key ${keyId} not found.`);

  const secretKey = await decryptKey(
    row.encryptedPrivateKey,
    row.encryptedPrivateKeyIv,
    encryptionKey
  );

  return {
    keyId: row.keyId,
    publicKey: decodeBase64(row.publicKey),
    secretKey,
    signature: decodeBase64(row.signature),
  };
}

/**
 * Load a one-time pre-key by ID (decrypted).
 */
export async function getPreKey(keyId: number, encryptionKey: CryptoKey): Promise<DecryptedPreKey> {
  const row = await db.preKeys.get(keyId);
  if (!row) throw new Error(`Pre-key ${keyId} not found.`);

  const secretKey = await decryptKey(
    row.encryptedPrivateKey,
    row.encryptedPrivateKeyIv,
    encryptionKey
  );

  return {
    keyId: row.keyId,
    publicKey: decodeBase64(row.publicKey),
    secretKey,
  };
}

/**
 * Delete a consumed one-time pre-key from local storage.
 */
export async function removePreKey(keyId: number): Promise<void> {
  await db.preKeys.delete(keyId);
}

/**
 * Load an encrypted session record for a remote peer.
 * Returns `null` if no session exists.
 */
export async function loadSession(
  remoteUserId: string,
  encryptionKey: CryptoKey
): Promise<SessionData | null> {
  const row = await db.sessions.get(remoteUserId);
  if (!row) return null;

  const json = await decrypt(row.encryptedRecord, row.encryptedRecordIv, encryptionKey);

  return JSON.parse(json) as SessionData;
}

/**
 * Persist (or update) an encrypted session record for a remote peer.
 */
export async function storeSession(
  remoteUserId: string,
  data: SessionData,
  encryptionKey: CryptoKey
): Promise<void> {
  const json = JSON.stringify(data);
  const { cipherText, iv } = await encrypt(json, encryptionKey);

  await db.sessions.put({
    id: remoteUserId,
    encryptedRecord: cipherText,
    encryptedRecordIv: iv,
  });
}
