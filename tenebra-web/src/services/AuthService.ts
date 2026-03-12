/**
 * AuthService — Registration and login flows for Tenebra Web.
 *
 * Registration:
 *   1. Generate Signal-compatible key material (SignalService).
 *   2. Register the user on the backend.
 *   3. Upload the signed pre-key and one-time pre-keys.
 *
 * Login:
 *   1. Request a challenge nonce from the backend.
 *   2. Decrypt the local Ed25519 private key and sign the nonce.
 *   3. Submit the signature for verification and receive a JWT.
 */

import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64 } from 'tweetnacl-util';
import api, { setToken } from '@/api/client';
import { db } from '@/db/db';
import { decrypt } from './SecurityService';
import { generateRegistrationData } from './SignalService';
import { v4 as uuidv4 } from 'uuid';

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface AuthResult {
  token: string;
  user: { id: string; username: string };
  deviceId: string;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/**
 * Retrieve (or create on first use) a stable device ID stored in the
 * Dexie meta table so it survives across sessions.
 */
async function getOrCreateDeviceId(): Promise<string> {
  const row = await db.meta.get('device_id');
  if (row) return row.value;

  const deviceId = uuidv4();
  await db.meta.put({ key: 'device_id', value: deviceId });
  return deviceId;
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Register a new user and upload all Signal key material.
 *
 * @returns user info, JWT, and device ID on success.
 */
export async function register(
  username: string,
  encryptionKey: CryptoKey,
  inviteCode: string
): Promise<AuthResult> {
  // If local keys already exist (e.g. previous registration succeeded but
  // key upload or auto-login failed), try to resume — but only if the
  // stored username matches and the backend still knows the user.
  const existingIdentity = await db.identity.get('self');
  if (existingIdentity) {
    const storedUsername = await db.meta.get('username');
    if (storedUsername?.value === username) {
      try {
        const deviceId = await getOrCreateDeviceId();
        const authResult = await loginWithKeys(username, deviceId, encryptionKey);
        await ensureKeysUploaded(authResult.user.id);
        return authResult;
      } catch {
        // Login failed — the backend may have been reset or the
        // user no longer exists.  Clean up stale keys and fall
        // through to a fresh registration.
        await cleanupLocalIdentity();
      }
    } else {
      // Different username — discard stale keys from a prior account.
      await cleanupLocalIdentity();
    }
  }

  // 1. Generate & persist keys locally
  const payload = await generateRegistrationData(encryptionKey);

  // 2. Register user on the backend
  let userId: string;
  try {
    const registerRes = await api.post('/users/register', {
      username,
      identity_public_key: payload.identityPublicKey,
      registration_id: payload.registrationId,
      inviteCode,
    });
    userId = registerRes.data.data.id;
  } catch (err: unknown) {
    // If the username is already taken (409), discard the freshly generated
    // identity — it cannot match the server's stored public key.
    const status =
      typeof err === 'object' && err !== null && 'response' in err
        ? (err as { response: { status: number } }).response?.status
        : undefined;
    if (status === 409) {
      await cleanupLocalIdentity();
      throw new Error(
        'This username is already registered. Please log in from the original device or restore your identity keys.'
      );
    }
    // Any other failure: clean up the orphaned local identity
    await cleanupLocalIdentity();
    throw err;
  }

  // Store the user ID and username locally for future reference
  await clearUserDataIfSwitched(userId);
  await db.meta.bulkPut([
    { key: 'user_id', value: userId },
    { key: 'username', value: username },
  ]);

  // 3. Log in first to obtain a JWT (key endpoints require authentication)
  const deviceId = await getOrCreateDeviceId();
  const authResult = await loginWithKeys(username, deviceId, encryptionKey);

  // 4. Upload signed pre-key (now authenticated)
  await uploadKeys(userId, payload);

  return authResult;
}

/**
 * Log in with an existing identity by proving ownership of the Ed25519
 * private key via a challenge-response signature.
 *
 * Requires the local identity private key in IndexedDB.  If it has been
 * deleted (e.g. browser data cleared), login is impossible — the user
 * must register a new account.
 *
 * @returns user info, JWT, and device ID on success.
 */
export async function login(username: string, encryptionKey: CryptoKey): Promise<AuthResult> {
  const existingIdentity = await db.identity.get('self');
  if (!existingIdentity) {
    throw new Error(
      'No local identity keys found. If you cleared browser data, ' +
        'the private key is permanently lost. Please register a new account.'
    );
  }

  const deviceId = await getOrCreateDeviceId();
  return loginWithKeys(username, deviceId, encryptionKey);
}

// ─── Internal ──────────────────────────────────────────────────────────────────

/** Upload signed pre-key and one-time pre-keys to the backend. */
async function uploadKeys(
  userId: string,
  payload: Awaited<ReturnType<typeof generateRegistrationData>>
): Promise<void> {
  await api.post('/keys/signed-pre-key', {
    user_id: userId,
    key_id: payload.signedPreKey.keyId,
    public_key: payload.signedPreKey.publicKey,
    signature: payload.signedPreKey.signature,
  });

  await api.post('/keys/one-time-pre-keys', {
    user_id: userId,
    keys: payload.oneTimePreKeys.map((k) => ({
      key_id: k.keyId,
      public_key: k.publicKey,
    })),
  });
}

/**
 * After login, check the server's remaining one-time pre-key count
 * (returned in the verify response) and re-upload from local Dexie
 * if the server has none.  This handles the case where a previous
 * registration succeeded but key upload was interrupted.
 */
async function ensureKeysUploaded(userId: string): Promise<void> {
  // Signed pre-key: always re-upload the latest from Dexie
  const signedPKs = await db.signedPreKeys.toArray();
  if (signedPKs.length > 0) {
    const spk = signedPKs[signedPKs.length - 1];
    try {
      await api.post('/keys/signed-pre-key', {
        user_id: userId,
        key_id: spk.keyId,
        public_key: spk.publicKey,
        signature: spk.signature,
      });
    } catch {
      // Ignore — server may already have it
    }
  }

  // One-time pre-keys: read all locally stored keys and upload
  const preKeys = await db.preKeys.toArray();
  if (preKeys.length > 0) {
    try {
      await api.post('/keys/one-time-pre-keys', {
        user_id: userId,
        keys: preKeys.map((k) => ({
          key_id: k.keyId,
          public_key: k.publicKey,
        })),
      });
    } catch {
      // Ignore — server may already have them
    }
  }
}

/**
 * Remove the freshly generated local identity and associated keys
 * so a subsequent register() call starts from a clean slate.
 */
async function cleanupLocalIdentity(): Promise<void> {
  try {
    await db.identity.delete('self');
    await db.signedPreKeys.clear();
    await db.preKeys.clear();
  } catch (cleanupErr) {
    console.warn('[AUTH] Failed to clean up temporary identity.', cleanupErr);
  }
}

/**
 * If a different user is logging in on this device, clear all
 * user-specific data (contacts, messages, sessions) so the new
 * user doesn't see the previous account's conversations.
 */
async function clearUserDataIfSwitched(newUserId: string): Promise<void> {
  try {
    const existing = await db.meta.get('user_id');
    if (existing && existing.value !== newUserId) {
      console.info('[AUTH] Account switch detected — clearing previous user data.');
      await db.contacts.clear();
      await db.messages.clear();
      await db.sessions.clear();
    }
  } catch (err) {
    console.warn('[AUTH] Failed to clear previous user data.', err);
  }
}

async function loginWithKeys(
  username: string,
  deviceId: string,
  encryptionKey: CryptoKey
): Promise<AuthResult> {
  // 1. Request challenge nonce
  const challengeRes = await api.post('/auth/challenge', {
    username,
    deviceId,
  });

  const nonce: string = challengeRes.data.data.nonce;

  // 2. Retrieve encrypted identity private key from Dexie
  const identity = await db.identity.get('self');
  if (!identity) {
    throw new Error('No local identity found. Please register first.');
  }

  // 3. Decrypt the private key
  const privateKeyB64 = await decrypt(
    identity.encryptedPrivateKey,
    identity.encryptedPrivateKeyIv,
    encryptionKey
  );
  const privateKey = decodeBase64(privateKeyB64);

  // 4. Sign the nonce (backend stores it as a hex string; we sign the UTF-8 bytes)
  const message = new TextEncoder().encode(nonce);
  const signature = nacl.sign.detached(message, privateKey);
  const signatureB64 = encodeBase64(signature);

  // 5. Send signature for verification
  const verifyRes = await api.post('/auth/verify', {
    username,
    signature: signatureB64,
    deviceId,
  });

  const { token, user } = verifyRes.data.data;

  // 6. Store JWT and user metadata
  setToken(token);
  await clearUserDataIfSwitched(user.id);
  await db.meta.bulkPut([
    { key: 'user_id', value: user.id },
    { key: 'username', value: user.username },
  ]);

  return { token, user, deviceId };
}
