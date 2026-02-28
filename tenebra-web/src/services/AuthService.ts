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
): Promise<AuthResult> {
    // Check if we already have local keys (e.g. previous registration succeeded
    // but auto-login failed). If so, skip key generation and go straight to login.
    const existingIdentity = await db.identity.get('self');
    if (existingIdentity) {
        console.info('[AUTH] Local identity already exists — skipping key generation, proceeding to login.');
        const deviceId = await getOrCreateDeviceId();
        return loginWithKeys(username, deviceId, encryptionKey);
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
        });
        userId = registerRes.data.data.id;
    } catch (err: unknown) {
        // If user already exists (409), retrieve their ID and skip to login
        const status =
            typeof err === 'object' && err !== null && 'response' in err
                ? (err as { response: { status: number } }).response?.status
                : undefined;
        if (status === 409) {
            console.info('[AUTH] User already registered on server — falling back to login.');
            const deviceId = await getOrCreateDeviceId();
            return loginWithKeys(username, deviceId, encryptionKey);
        }
        throw err;
    }

    // Store the user ID and username locally for future reference
    await db.meta.bulkPut([
        { key: 'user_id', value: userId },
        { key: 'username', value: username },
    ]);

    // 3. Log in first to obtain a JWT (key endpoints require authentication)
    const deviceId = await getOrCreateDeviceId();
    const authResult = await loginWithKeys(username, deviceId, encryptionKey);

    // 4. Upload signed pre-key (now authenticated)
    await api.post('/keys/signed-pre-key', {
        user_id: userId,
        key_id: payload.signedPreKey.keyId,
        public_key: payload.signedPreKey.publicKey,
        signature: payload.signedPreKey.signature,
    });

    // 5. Upload one-time pre-keys (now authenticated)
    await api.post('/keys/one-time-pre-keys', {
        user_id: userId,
        keys: payload.oneTimePreKeys.map((k) => ({
            key_id: k.keyId,
            public_key: k.publicKey,
        })),
    });

    return authResult;
}

/**
 * Log in with an existing identity by proving ownership of the Ed25519
 * private key via a challenge-response signature.
 *
 * @returns user info, JWT, and device ID on success.
 */
export async function login(
    username: string,
    encryptionKey: CryptoKey,
): Promise<AuthResult> {
    const deviceId = await getOrCreateDeviceId();
    return loginWithKeys(username, deviceId, encryptionKey);
}

// ─── Internal ──────────────────────────────────────────────────────────────────

async function loginWithKeys(
    username: string,
    deviceId: string,
    encryptionKey: CryptoKey,
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
        encryptionKey,
    );
    const privateKey = decodeBase64(privateKeyB64);

    // 4. Sign the nonce (backend stores it as a hex string; we sign the UTF-8 bytes)
    const message = new TextEncoder().encode(nonce);
    const signature = nacl.sign.detached(message, privateKey);
    const signatureB64 = encodeBase64(signature);

    // ── Diagnostic: verify locally before sending to backend ──
    const localPub = decodeBase64(identity.publicKey);
    const localValid = nacl.sign.detached.verify(message, signature, localPub);
    if (!localValid) {
        console.error('[AUTH] Local signature verification FAILED — private key may be corrupted');
        console.error('[AUTH] privateKey.length:', privateKey.length);
        console.error('[AUTH] publicKey (b64):', identity.publicKey);
    } else {
        console.info('[AUTH] Local signature verification passed');
    }

    // 5. Send signature for verification
    const verifyRes = await api.post('/auth/verify', {
        username,
        signature: signatureB64,
        deviceId,
    });

    const { token, user } = verifyRes.data.data;

    // 6. Store JWT and user metadata
    setToken(token);
    await db.meta.bulkPut([
        { key: 'user_id', value: user.id },
        { key: 'username', value: user.username },
    ]);

    return { token, user, deviceId };
}
