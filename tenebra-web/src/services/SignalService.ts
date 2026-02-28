/**
 * SignalService — Key generation for the Signal-compatible identity layer.
 *
 * Uses **tweetnacl** (pure JS, browser-safe) for:
 *   • Ed25519   identity key pair   (signing / verification)
 *   • X25519    pre-key pairs       (Diffie-Hellman key agreement)
 *
 * All private keys are encrypted with AES-GCM (via SecurityService)
 * before being stored in Dexie.  Only **public** keys and signatures
 * are returned in the payload intended for the backend.
 */

import nacl from 'tweetnacl';
import { encodeBase64 } from 'tweetnacl-util';
import { encrypt } from './SecurityService';
import { db } from '@/db/db';

// ─── Constants ─────────────────────────────────────────────────────────────────

/** Number of one-time pre-keys to generate per batch. */
const ONE_TIME_PRE_KEY_COUNT = 100;

/** Starting key ID for one-time pre-keys. */
const OTP_KEY_START_ID = 1;

/** Starting key ID for the first signed pre-key. */
const SIGNED_PRE_KEY_ID = 1;

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface RegistrationPayload {
    /** Base64-encoded 32-byte Ed25519 public identity key. */
    identityPublicKey: string;
    /** 16-bit unsigned registration ID. */
    registrationId: number;
    /** Signed pre-key ready for upload. */
    signedPreKey: {
        keyId: number;
        publicKey: string;
        signature: string;
    };
    /** One-time pre-keys ready for upload. */
    oneTimePreKeys: Array<{
        keyId: number;
        publicKey: string;
    }>;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/** Encrypt a Uint8Array private key and return Base64 ciphertext + iv. */
async function encryptPrivateKey(
    privateKey: Uint8Array,
    encryptionKey: CryptoKey,
): Promise<{ cipherText: string; iv: string }> {
    // Encode private key bytes as Base64 before feeding to AES-GCM
    const b64 = encodeBase64(privateKey);
    return encrypt(b64, encryptionKey);
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Generate a full set of Signal-compatible registration keys.
 *
 * 1. Create an Ed25519 identity key pair + random registration ID.
 * 2. Create one X25519 signed pre-key, signed by the identity key.
 * 3. Create {@link ONE_TIME_PRE_KEY_COUNT} X25519 one-time pre-keys.
 * 4. Encrypt all private keys and persist them in Dexie.
 * 5. Return the **public** payload for the backend.
 */
export async function generateRegistrationData(
    encryptionKey: CryptoKey,
): Promise<RegistrationPayload> {
    // ── 1. Identity key pair (Ed25519) ──────────────────────────────────────
    const identityKeyPair = nacl.sign.keyPair();
    const registrationId = crypto.getRandomValues(new Uint16Array(1))[0];

    // ── 2. Signed pre-key (X25519) ─────────────────────────────────────────
    const signedPreKeyPair = nacl.box.keyPair();
    // Sign the public key of the signed pre-key with the identity secret key
    const signedPreKeySignature = nacl.sign.detached(
        signedPreKeyPair.publicKey,
        identityKeyPair.secretKey,
    );

    // ── 3. One-time pre-keys (X25519) ──────────────────────────────────────
    const oneTimePreKeys: Array<{
        keyId: number;
        publicKey: Uint8Array;
        secretKey: Uint8Array;
    }> = [];

    for (let i = 0; i < ONE_TIME_PRE_KEY_COUNT; i++) {
        const kp = nacl.box.keyPair();
        oneTimePreKeys.push({
            keyId: OTP_KEY_START_ID + i,
            publicKey: kp.publicKey,
            secretKey: kp.secretKey,
        });
    }

    // ── 4. Encrypt & persist private keys ───────────────────────────────────

    // Identity
    const encIdentity = await encryptPrivateKey(identityKeyPair.secretKey, encryptionKey);
    await db.identity.put({
        id: 'self',
        registrationId,
        publicKey: encodeBase64(identityKeyPair.publicKey),
        encryptedPrivateKey: encIdentity.cipherText,
        encryptedPrivateKeyIv: encIdentity.iv,
    });

    // Signed pre-key
    const encSignedPK = await encryptPrivateKey(signedPreKeyPair.secretKey, encryptionKey);
    await db.signedPreKeys.put({
        keyId: SIGNED_PRE_KEY_ID,
        publicKey: encodeBase64(signedPreKeyPair.publicKey),
        encryptedPrivateKey: encSignedPK.cipherText,
        encryptedPrivateKeyIv: encSignedPK.iv,
        signature: encodeBase64(signedPreKeySignature),
    });

    // One-time pre-keys (batch insert)
    const preKeyRows = await Promise.all(
        oneTimePreKeys.map(async (pk) => {
            const enc = await encryptPrivateKey(pk.secretKey, encryptionKey);
            return {
                keyId: pk.keyId,
                publicKey: encodeBase64(pk.publicKey),
                encryptedPrivateKey: enc.cipherText,
                encryptedPrivateKeyIv: enc.iv,
            };
        }),
    );
    await db.preKeys.bulkPut(preKeyRows);

    // ── 5. Build backend payload (public keys only) ─────────────────────────
    return {
        identityPublicKey: encodeBase64(identityKeyPair.publicKey),
        registrationId,
        signedPreKey: {
            keyId: SIGNED_PRE_KEY_ID,
            publicKey: encodeBase64(signedPreKeyPair.publicKey),
            signature: encodeBase64(signedPreKeySignature),
        },
        oneTimePreKeys: oneTimePreKeys.map((pk) => ({
            keyId: pk.keyId,
            publicKey: encodeBase64(pk.publicKey),
        })),
    };
}
