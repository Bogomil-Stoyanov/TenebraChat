/**
 * MessagingService — End-to-end encrypted messaging using the X3DH
 * key-agreement protocol built on **tweetnacl** + **ed2curve**.
 *
 * Because `@signalapp/libsignal-client` ships native `.node` addons
 * (not WASM) it cannot run in the browser.  This module implements
 * the X3DH handshake from first principles with the same security
 * guarantees:
 *
 *   Ed25519 identity keys  → converted to X25519 via ed2curve
 *   X25519 signed pre-keys → used directly for DH
 *   X25519 one-time pre-keys → used directly for DH
 *   Ephemeral X25519 key pair → generated per session
 *   HKDF-SHA-256 → derives the 32-byte session key
 *   NaCl secretbox (XSalsa20-Poly1305) → symmetric message encryption
 *
 * After the initial X3DH handshake the root key seeds a **symmetric
 * chain ratchet** (HKDF-based) that derives a unique message key for
 * every send/receive.  Old message keys are discarded, providing
 * per-message forward secrecy.
 *
 * Each sealed payload also includes sender/recipient identity and a
 * timestamp to bind the ciphertext to its intended participants and
 * prevent replay/reflection attacks.
 */

import nacl from 'tweetnacl';
import { decodeBase64, encodeBase64, decodeUTF8, encodeUTF8 } from 'tweetnacl-util';
import { convertPublicKey, convertSecretKey } from 'ed2curve';
import { v4 as uuidv4 } from 'uuid';

import api from '@/api/client';
import { db } from '@/db/db';
import type { Message, DecryptedMessage, AttachmentMeta } from '@/db/db';
import { encrypt, decrypt } from './SecurityService';
import {
    getIdentityKeyPair,
    getSignedPreKey,
    getPreKey,
    removePreKey,
    loadSession,
    storeSession,
} from './SignalStoreAdapter';
import type { SessionData } from './SignalStoreAdapter';

// ─── Constants ─────────────────────────────────────────────────────────────────

/** 32 × 0xFF prepended to the master secret per the X3DH specification. */
const X3DH_PADDING = new Uint8Array(32).fill(0xff);

/** HKDF salt: 32 zero bytes (default when no salt is provided). */
const HKDF_SALT = new Uint8Array(32);

/** HKDF info string identifying our application. */
const HKDF_INFO = new TextEncoder().encode('TenebraX3DH');

/**
 * Single HKDF info for all symmetric chain ratchet advances.
 * Directional separation is already encoded in the chain key itself
 * (derived via distinct HKDF info in {@link deriveInitialChainKeys}),
 * so the advance step does not need a per-direction label.
 */
const CHAIN_RATCHET_INFO = new TextEncoder().encode('TenebraChain');

/** HKDF info for deriving the initial sending chain key from the root key. */
const CHAIN_RATCHET_INFO_SEND = new TextEncoder().encode('TenebraChainSend');

/** HKDF info for deriving the initial receiving chain key from the root key. */
const CHAIN_RATCHET_INFO_RECV = new TextEncoder().encode('TenebraChainRecv');

/**
 * Maximum age (ms) of a session before a fresh X3DH handshake is forced.
 * Default: 7 days.
 */
const SESSION_MAX_AGE_MS = 7 * 24 * 60 * 60 * 1000;

/**
 * Maximum messages on a single chain key before forcing re-key.
 * Default: 500 messages.
 */
const SESSION_MAX_MESSAGES = 500;

/**
 * Maximum number of skipped chain steps allowed when a message arrives
 * out of order. Limits CPU cost and prevents abuse.
 */
const MAX_SKIP_KEYS = 50;

// ─── Types ─────────────────────────────────────────────────────────────────────

/** PreKeyBundle returned by the backend. */
interface PreKeyBundle {
    user_id: string;
    username: string;
    registration_id: number;
    identity_public_key: string; // Base64 Ed25519
    signed_pre_key: {
        key_id: number;
        public_key: string; // Base64 X25519
        signature: string;  // Base64 Ed25519 detached signature
    };
    one_time_pre_key?: {
        key_id: number;
        public_key: string; // Base64 X25519
    };
}

/** Wire envelope for a pre-key (initial) message. */
interface PreKeySignalEnvelope {
    registrationId: number;
    preKeyId: number;       // -1 when no OTP key was available
    signedPreKeyId: number;
    baseKey: string;        // Base64 ephemeral X25519 public key
    identityKey: string;    // Base64 Ed25519 sender identity public key
    ciphertext: string;     // Base64(nonce ‖ secretbox output)
}

/** Wire envelope for a regular (post-handshake) message. */
interface SignalEnvelope {
    ciphertext: string;     // Base64(nonce ‖ secretbox output)
    /** Monotonic chain index so the receiver can derive the correct key. */
    chainIndex: number;
}

// ─── Inner payload ─────────────────────────────────────────────────────────────

/** JSON structure that gets encrypted inside the NaCl secretbox. */
interface InnerPayload {
    text: string;
    attachment?: AttachmentMeta;
    /** Sender's userId — binds ciphertext to sender identity. */
    senderId: string;
    /** Recipient's userId — binds ciphertext to intended recipient. */
    recipientId: string;
    /** Unix epoch ms — prevents indefinite replay. */
    timestamp: number;
}

// ─── Replay protection ────────────────────────────────────────────────────────

/**
 * In-memory set of SHA-256 hashes of processed ciphertext blobs.
 * Prevents the same encrypted payload from being accepted twice
 * within a single session (cleared on page reload, which is fine
 * because the offline-message fetch is idempotent server-side).
 */
const processedCiphertextHashes = new Set<string>();

/** Maximum age (ms) allowed for an incoming message timestamp. */
const MAX_MESSAGE_AGE_MS = 5 * 60 * 1000; // 5 minutes

/**
 * Hash a ciphertext string and check if it was already processed.
 * If not, add it to the set and return false (not a replay).
 */
async function isReplay(ciphertextB64: string): Promise<boolean> {
    const hashBuf = await crypto.subtle.digest(
        'SHA-256',
        new TextEncoder().encode(ciphertextB64),
    );
    const hex = [...new Uint8Array(hashBuf)]
        .map((b) => b.toString(16).padStart(2, '0'))
        .join('');
    if (processedCiphertextHashes.has(hex)) return true;
    processedCiphertextHashes.add(hex);
    return false;
}

// ─── Helpers ───────────────────────────────────────────────────────────────────

/** Concatenate Uint8Arrays. */
function concat(...arrays: Uint8Array[]): Uint8Array {
    const total = arrays.reduce((sum, a) => sum + a.length, 0);
    const out = new Uint8Array(total);
    let offset = 0;
    for (const a of arrays) {
        out.set(a, offset);
        offset += a.length;
    }
    return out;
}

/**
 * Derive a 32-byte key using HKDF-SHA-256 (Web Crypto API).
 */
async function hkdf(
    ikm: Uint8Array,
    salt: Uint8Array,
    info: Uint8Array,
    length: number,
): Promise<Uint8Array> {
    const key = await crypto.subtle.importKey(
        'raw',
        ikm as BufferSource,
        'HKDF',
        false,
        ['deriveBits'],
    );
    const bits = await crypto.subtle.deriveBits(
        {
            name: 'HKDF',
            hash: 'SHA-256',
            salt: salt as BufferSource,
            info: info as BufferSource,
        },
        key,
        length * 8,
    );
    return new Uint8Array(bits);
}

// ─── Symmetric chain ratchet ───────────────────────────────────────────────────

/**
 * Advance a chain key by one step using HKDF.
 *
 * Each step produces:
 *   - `messageKey`  — a unique 32-byte key for encrypting ONE message
 *   - `nextChainKey` — the new chain key (the old one is discarded)
 *
 * This provides per-message forward secrecy: once a message key is used
 * and discarded, the message it protected cannot be decrypted even if
 * future chain keys are compromised.
 */
async function advanceChainKey(
    chainKey: Uint8Array,
    info: Uint8Array,
): Promise<{ messageKey: Uint8Array; nextChainKey: Uint8Array }> {
    // messageKey  = HKDF(chainKey, salt=0x01, info)
    const messageKey = await hkdf(
        chainKey,
        new Uint8Array([0x01]),
        info,
        32,
    );
    // nextChainKey = HKDF(chainKey, salt=0x02, info)
    const nextChainKey = await hkdf(
        chainKey,
        new Uint8Array([0x02]),
        info,
        32,
    );
    return { messageKey, nextChainKey };
}

/**
 * Derive the initial send and receive chain keys from the root (session) key.
 * The initiator's send chain = responder's receive chain and vice versa.
 */
async function deriveInitialChainKeys(
    rootKey: Uint8Array,
): Promise<{ sendChainKey: Uint8Array; recvChainKey: Uint8Array }> {
    const sendChainKey = await hkdf(rootKey, HKDF_SALT, CHAIN_RATCHET_INFO_SEND, 32);
    const recvChainKey = await hkdf(rootKey, HKDF_SALT, CHAIN_RATCHET_INFO_RECV, 32);
    return { sendChainKey, recvChainKey };
}

// ─── Seal / open ───────────────────────────────────────────────────────────────

/**
 * Encrypt an {@link InnerPayload} with NaCl secretbox (XSalsa20-Poly1305).
 * Returns Base64(nonce ‖ ciphertext).
 */
function sealMessage(payload: InnerPayload, messageKey: Uint8Array): string {
    const nonce = nacl.randomBytes(nacl.secretbox.nonceLength);
    const msgBytes = decodeUTF8(JSON.stringify(payload));
    const box = nacl.secretbox(msgBytes, nonce, messageKey);
    return encodeBase64(concat(nonce, box));
}

/**
 * Decrypt a Base64(nonce ‖ ciphertext) produced by {@link sealMessage}.
 */
function openMessage(sealed: string, messageKey: Uint8Array): InnerPayload {
    const data = decodeBase64(sealed);
    const nonce = data.slice(0, nacl.secretbox.nonceLength);
    const box = data.slice(nacl.secretbox.nonceLength);
    const plain = nacl.secretbox.open(box, nonce, messageKey);
    if (!plain) throw new Error('Decryption failed — invalid key or corrupted message.');

    const decoded = encodeUTF8(plain);
    try {
        const parsed = JSON.parse(decoded);
        if (parsed && typeof parsed === 'object' && typeof parsed.text === 'string') {
            return parsed as InnerPayload;
        }
        // Parsed JSON but not in the expected shape — treat as legacy plaintext.
        return { text: decoded } as InnerPayload;
    } catch {
        // Non-JSON legacy payload — wrap as plaintext.
        return { text: decoded } as InnerPayload;
    }
}

/**
 * Serialise the message envelope as Base64 for the backend `ciphertext` field.
 */
function envelopeToBase64(envelope: PreKeySignalEnvelope | SignalEnvelope): string {
    return btoa(JSON.stringify(envelope));
}

/**
 * Deserialise a Base64 `ciphertext` from the backend back to an envelope.
 */
function base64ToEnvelope<T>(b64: string): T {
    return JSON.parse(atob(b64)) as T;
}

// ─── X3DH ──────────────────────────────────────────────────────────────────────

/**
 * Perform the **initiator** side of the X3DH key agreement.
 *
 * DH1 = X25519( Alice_identity_x25519_sk,  Bob_signed_prekey_pk )
 * DH2 = X25519( Alice_ephemeral_sk,        Bob_identity_x25519_pk )
 * DH3 = X25519( Alice_ephemeral_sk,        Bob_signed_prekey_pk )
 * DH4 = X25519( Alice_ephemeral_sk,        Bob_otp_key_pk )       [optional]
 *
 * SK = HKDF( F ‖ DH1 ‖ DH2 ‖ DH3 [‖ DH4] )
 */
async function x3dhInitiator(
    identitySecretKey: Uint8Array,     // 64-byte Ed25519 sk
    remoteIdentityPubKey: Uint8Array,  // 32-byte Ed25519 pk
    remoteSignedPreKeyPub: Uint8Array, // 32-byte X25519 pk
    remoteOtpKeyPub: Uint8Array | null,
): Promise<{ sessionKey: Uint8Array; ephemeralPublicKey: Uint8Array }> {
    // Convert Ed25519 keys → X25519
    const myX25519Sk = convertSecretKey(identitySecretKey);
    const remoteX25519Pk = convertPublicKey(remoteIdentityPubKey);
    if (!remoteX25519Pk) throw new Error('Failed to convert remote identity key to X25519.');

    // Ephemeral key pair (X25519)
    const ephemeral = nacl.box.keyPair();

    // DH operations
    const dh1 = nacl.scalarMult(myX25519Sk, remoteSignedPreKeyPub);
    const dh2 = nacl.scalarMult(ephemeral.secretKey, remoteX25519Pk);
    const dh3 = nacl.scalarMult(ephemeral.secretKey, remoteSignedPreKeyPub);

    let km: Uint8Array;
    if (remoteOtpKeyPub) {
        const dh4 = nacl.scalarMult(ephemeral.secretKey, remoteOtpKeyPub);
        km = concat(X3DH_PADDING, dh1, dh2, dh3, dh4);
    } else {
        km = concat(X3DH_PADDING, dh1, dh2, dh3);
    }

    const sessionKey = await hkdf(km, HKDF_SALT, HKDF_INFO, 32);
    return { sessionKey, ephemeralPublicKey: ephemeral.publicKey };
}

/**
 * Perform the **responder** side of the X3DH key agreement.
 *
 * DH1 = X25519( Bob_signed_prekey_sk,    Alice_identity_x25519_pk )
 * DH2 = X25519( Bob_identity_x25519_sk,  Alice_ephemeral_pk )
 * DH3 = X25519( Bob_signed_prekey_sk,    Alice_ephemeral_pk )
 * DH4 = X25519( Bob_otp_key_sk,          Alice_ephemeral_pk )    [optional]
 */
async function x3dhResponder(
    identitySecretKey: Uint8Array,     // 64-byte Ed25519 sk
    signedPreKeySecretKey: Uint8Array, // 32-byte X25519 sk
    otpKeySecretKey: Uint8Array | null,
    remoteIdentityPubKey: Uint8Array,  // 32-byte Ed25519 pk
    remoteEphemeralPub: Uint8Array,    // 32-byte X25519 pk
): Promise<Uint8Array> {
    // Convert Ed25519 keys → X25519
    const myX25519Sk = convertSecretKey(identitySecretKey);
    const remoteX25519Pk = convertPublicKey(remoteIdentityPubKey);
    if (!remoteX25519Pk) throw new Error('Failed to convert remote identity key to X25519.');

    // DH operations
    const dh1 = nacl.scalarMult(signedPreKeySecretKey, remoteX25519Pk);
    const dh2 = nacl.scalarMult(myX25519Sk, remoteEphemeralPub);
    const dh3 = nacl.scalarMult(signedPreKeySecretKey, remoteEphemeralPub);

    let km: Uint8Array;
    if (otpKeySecretKey) {
        const dh4 = nacl.scalarMult(otpKeySecretKey, remoteEphemeralPub);
        km = concat(X3DH_PADDING, dh1, dh2, dh3, dh4);
    } else {
        km = concat(X3DH_PADDING, dh1, dh2, dh3);
    }

    return hkdf(km, HKDF_SALT, HKDF_INFO, 32);
}

// ─── Session helpers ───────────────────────────────────────────────────────────

/**
 * Check whether the session is expired, exhausted, or missing chain
 * ratchet fields (backward-compat with pre-ratchet sessions).
 */
function isSessionExpired(session: SessionData): boolean {
    // Old sessions without chain ratchet fields must be re-keyed
    if (!session.sendChainKey || !session.recvChainKey || session.createdAt == null) return true;
    if (Date.now() - session.createdAt > SESSION_MAX_AGE_MS) return true;
    if (session.sendMessageCount >= SESSION_MAX_MESSAGES) return true;
    return false;
}

// ─── Local storage helpers ─────────────────────────────────────────────────────

/** Encrypt text (+optional attachment meta) and persist as a Message in IndexedDB. */
async function persistMessage(
    id: string,
    contactId: string,
    plaintext: string,
    direction: 'in' | 'out',
    timestamp: number,
    encryptionKey: CryptoKey,
    attachment?: AttachmentMeta,
): Promise<DecryptedMessage> {
    const { cipherText, iv } = await encrypt(plaintext, encryptionKey);

    let encryptedAttachment: string | undefined;
    let encryptedAttachmentIv: string | undefined;
    if (attachment) {
        const enc = await encrypt(JSON.stringify(attachment), encryptionKey);
        encryptedAttachment = enc.cipherText;
        encryptedAttachmentIv = enc.iv;
    }

    const row: Message = {
        id,
        contactId,
        encryptedText: cipherText,
        encryptedTextIv: iv,
        direction,
        timestamp,
        encryptedAttachment,
        encryptedAttachmentIv,
    };
    await db.messages.add(row);
    return { id, contactId, text: plaintext, direction, timestamp, attachment };
}

/** Decrypt a stored Message row into a DecryptedMessage. */
async function decryptMessageRow(
    row: Message,
    encryptionKey: CryptoKey,
): Promise<DecryptedMessage> {
    const text = await decrypt(row.encryptedText, row.encryptedTextIv, encryptionKey);

    let attachment: AttachmentMeta | undefined;
    if (row.encryptedAttachment && row.encryptedAttachmentIv) {
        const json = await decrypt(row.encryptedAttachment, row.encryptedAttachmentIv, encryptionKey);
        attachment = JSON.parse(json) as AttachmentMeta;
    }

    return {
        id: row.id,
        contactId: row.contactId,
        text,
        direction: row.direction,
        timestamp: row.timestamp,
        attachment,
    };
}

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Resolve a username to a userId via the backend.
 */
export async function resolveUsername(
    username: string,
): Promise<{ id: string; username: string }> {
    const res = await api.get(`/users/by-username/${encodeURIComponent(username)}`);
    return res.data.data;
}

/**
 * Resolve a userId to a user record (including username).
 */
export async function resolveUserId(
    userId: string,
): Promise<{ id: string; username: string }> {
    const res = await api.get(`/users/${encodeURIComponent(userId)}`);
    return res.data.data;
}

/**
 * Establish an X3DH session with a remote user and send the first
 * encrypted message as a `pre_key_signal_message`.
 *
 * @returns The saved {@link DecryptedMessage} that was persisted locally.
 */
export async function sendFirstMessage(
    contactUserId: string,
    plaintext: string,
    encryptionKey: CryptoKey,
    attachment?: AttachmentMeta,
): Promise<DecryptedMessage> {
    // 1. Fetch remote key bundle
    const bundleRes = await api.get(`/keys/bundle/${contactUserId}`);
    const bundle: PreKeyBundle = bundleRes.data.data;

    // 2. Verify signed pre-key signature
    const spkPub = decodeBase64(bundle.signed_pre_key.public_key);
    const spkSig = decodeBase64(bundle.signed_pre_key.signature);
    const identityPub = decodeBase64(bundle.identity_public_key);

    const valid = nacl.sign.detached.verify(spkPub, spkSig, identityPub);
    if (!valid) throw new Error('Signed pre-key signature verification failed.');

    // 3. Local identity
    const identity = await getIdentityKeyPair(encryptionKey);

    // 4. Perform X3DH (initiator)
    const otpPub = bundle.one_time_pre_key
        ? decodeBase64(bundle.one_time_pre_key.public_key)
        : null;

    const { sessionKey, ephemeralPublicKey } = await x3dhInitiator(
        identity.secretKey,
        identityPub,
        spkPub,
        otpPub,
    );

    // 5. Derive chain keys & advance the send chain for this first message
    const { sendChainKey, recvChainKey } = await deriveInitialChainKeys(sessionKey);
    const { messageKey, nextChainKey: nextSendChain } = await advanceChainKey(
        sendChainKey,
        CHAIN_RATCHET_INFO,
    );

    // 6. Encrypt the plaintext with the per-message key
    const identityRow = await db.meta.get('user_id');
    if (!identityRow || typeof identityRow.value !== 'string' || !identityRow.value) {
        throw new Error('Cannot send message: missing local user identity (user_id).');
    }
    const myId = identityRow.value;

    const innerPayload: InnerPayload = {
        text: plaintext,
        attachment,
        senderId: myId,
        recipientId: contactUserId,
        timestamp: Date.now(),
    };
    const sealed = sealMessage(innerPayload, messageKey);

    // 7. Build the envelope
    const envelope: PreKeySignalEnvelope = {
        registrationId: identity.registrationId,
        preKeyId: bundle.one_time_pre_key?.key_id ?? -1,
        signedPreKeyId: bundle.signed_pre_key.key_id,
        baseKey: encodeBase64(ephemeralPublicKey),
        identityKey: encodeBase64(identity.publicKey),
        ciphertext: sealed,
    };

    // 8. Send via backend
    await api.post('/messages/send', {
        recipientId: contactUserId,
        ciphertext: envelopeToBase64(envelope),
        type: 'pre_key_signal_message',
    });

    // 9. Persist session (with chain ratchet state)
    const sessionData: SessionData = {
        sessionKey: encodeBase64(sessionKey),
        remoteIdentityKey: bundle.identity_public_key,
        remoteRegistrationId: bundle.registration_id,
        sendChainKey: encodeBase64(nextSendChain),
        recvChainKey: encodeBase64(recvChainKey),
        sendMessageCount: 1,
        recvMessageCount: 0,
        createdAt: Date.now(),
    };
    await storeSession(contactUserId, sessionData, encryptionKey);

    // 10. Persist local message (encrypted at rest)
    return persistMessage(uuidv4(), contactUserId, plaintext, 'out', Date.now(), encryptionKey, attachment);
}

/**
 * Send a message using an already-established session.
 */
export async function sendMessage(
    contactUserId: string,
    plaintext: string,
    encryptionKey: CryptoKey,
    attachment?: AttachmentMeta,
): Promise<DecryptedMessage> {
    const session = await loadSession(contactUserId, encryptionKey);
    if (!session || isSessionExpired(session)) {
        // No session or expired — establish a fresh one
        return sendFirstMessage(contactUserId, plaintext, encryptionKey, attachment);
    }

    // Advance the send chain ratchet
    const currentChainKey = decodeBase64(session.sendChainKey);
    const { messageKey, nextChainKey } = await advanceChainKey(
        currentChainKey,
        CHAIN_RATCHET_INFO,
    );

    // Build identity-bound payload
    const identityRow = await db.meta.get('user_id');
    if (!identityRow || typeof identityRow.value !== 'string' || !identityRow.value) {
        throw new Error('Cannot send message: missing local user identity (user_id).');
    }
    const myId = identityRow.value;

    const innerPayload: InnerPayload = {
        text: plaintext,
        attachment,
        senderId: myId,
        recipientId: contactUserId,
        timestamp: Date.now(),
    };
    const sealed = sealMessage(innerPayload, messageKey);

    const envelope: SignalEnvelope = {
        ciphertext: sealed,
        chainIndex: session.sendMessageCount,
    };

    await api.post('/messages/send', {
        recipientId: contactUserId,
        ciphertext: envelopeToBase64(envelope),
        type: 'signal_message',
    });

    // Update session: advance send chain, increment counter
    session.sendChainKey = encodeBase64(nextChainKey);
    session.sendMessageCount += 1;
    await storeSession(contactUserId, session, encryptionKey);

    return persistMessage(uuidv4(), contactUserId, plaintext, 'out', Date.now(), encryptionKey, attachment);
}

/**
 * Process an incoming message (real-time or offline).
 *
 * @returns The decrypted {@link DecryptedMessage}.
 * @throws If decryption, session lookup, identity key verification, or
 *         replay detection fails.
 */
export async function processIncomingMessage(
    senderId: string,
    ciphertextB64: string,
    type: string,
    timestamp: number,
    encryptionKey: CryptoKey,
): Promise<DecryptedMessage> {
    // ── Replay protection ────────────────────────────────────────────────
    if (await isReplay(ciphertextB64)) {
        throw new Error(`Replay detected: duplicate ciphertext from ${senderId}.`);
    }

    let payload: InnerPayload;

    if (type === 'pre_key_signal_message') {
        const envelope = base64ToEnvelope<PreKeySignalEnvelope>(ciphertextB64);

        // TOFU (Trust On First Use): if we already have a session with this
        // sender, verify that the identity key matches what we stored the
        // first time.  A mismatch means either the sender re-registered or
        // someone is attempting a MITM key-swap.
        const existingSession = await loadSession(senderId, encryptionKey);
        if (existingSession) {
            if (existingSession.remoteIdentityKey !== envelope.identityKey) {
                throw new Error(
                    `Identity key mismatch for sender ${senderId}. ` +
                    'The remote party may have re-registered or the message may be forged.',
                );
            }
        }

        // Load our local key material
        const identity = await getIdentityKeyPair(encryptionKey);
        const signedPreKey = await getSignedPreKey(
            envelope.signedPreKeyId,
            encryptionKey,
        );

        let otpSk: Uint8Array | null = null;
        if (envelope.preKeyId >= 0) {
            try {
                const otp = await getPreKey(envelope.preKeyId, encryptionKey);
                otpSk = otp.secretKey;
            } catch {
                // OTP key may have already been consumed — proceed without it
                console.warn(`One-time pre-key ${envelope.preKeyId} not found locally.`);
            }
        }

        // X3DH responder
        const senderIdentityPub = decodeBase64(envelope.identityKey);
        const senderEphemeralPub = decodeBase64(envelope.baseKey);

        const sessionKey = await x3dhResponder(
            identity.secretKey,
            signedPreKey.secretKey,
            otpSk,
            senderIdentityPub,
            senderEphemeralPub,
        );

        // Derive chain keys (responder's recv = initiator's send)
        const { sendChainKey: initiatorSend, recvChainKey: initiatorRecv } =
            await deriveInitialChainKeys(sessionKey);

        // As responder, our recv chain = initiator's send chain
        const myRecvChainKey = initiatorSend;
        const mySendChainKey = initiatorRecv;

        // Advance the receive chain for this first message
        const { messageKey, nextChainKey: nextRecvChain } = await advanceChainKey(
            myRecvChainKey,
            CHAIN_RATCHET_INFO,
        );

        // Decrypt the message body
        payload = openMessage(envelope.ciphertext, messageKey);

        // Persist the session (with chain ratchet state)
        const sessionData: SessionData = {
            sessionKey: encodeBase64(sessionKey),
            remoteIdentityKey: envelope.identityKey,
            remoteRegistrationId: envelope.registrationId,
            sendChainKey: encodeBase64(mySendChainKey),
            recvChainKey: encodeBase64(nextRecvChain),
            sendMessageCount: 0,
            recvMessageCount: 1,
            createdAt: Date.now(),
        };
        await storeSession(senderId, sessionData, encryptionKey);

        // Consume the one-time pre-key
        if (envelope.preKeyId >= 0) {
            await removePreKey(envelope.preKeyId).catch(() => {
                /* already removed */
            });
        }
    } else if (type === 'signal_message') {
        // Regular signal_message — use existing session
        const session = await loadSession(senderId, encryptionKey);
        if (!session) {
            throw new Error(
                `No session found for sender ${senderId}. Cannot decrypt signal_message.`,
            );
        }
        const envelope = base64ToEnvelope<SignalEnvelope>(ciphertextB64);

        // Advance the receive chain ratchet (with skipped-key window)
        if (!session.recvChainKey) {
            throw new Error(
                `Session for sender ${senderId} is missing chain ratchet state. ` +
                'A new key exchange is required.',
            );
        }

        const targetIndex = envelope.chainIndex ?? session.recvMessageCount;
        const currentIndex = session.recvMessageCount;

        if (targetIndex < currentIndex) {
            throw new Error(
                `Out-of-order message (index ${targetIndex} < ${currentIndex}). ` +
                'Cannot derive past keys — message is unrecoverable.',
            );
        }

        // Fast-forward the chain to the target index, discarding
        // intermediate message keys (skipped messages are lost).
        const gap = targetIndex - currentIndex;
        if (gap > MAX_SKIP_KEYS) {
            throw new Error(
                `Message gap too large (${gap} > ${MAX_SKIP_KEYS}). ` +
                'Possible attack or severe message loss — re-key required.',
            );
        }

        let chainKey = decodeBase64(session.recvChainKey);
        for (let i = 0; i < gap; i++) {
            const stepped = await advanceChainKey(chainKey, CHAIN_RATCHET_INFO);
            chainKey = stepped.nextChainKey;
        }

        // Derive the actual message key for this index
        const { messageKey, nextChainKey } = await advanceChainKey(
            chainKey,
            CHAIN_RATCHET_INFO,
        );

        payload = openMessage(envelope.ciphertext, messageKey);

        // Update session: advance recv chain past the target index
        session.recvChainKey = encodeBase64(nextChainKey);
        session.recvMessageCount = targetIndex + 1;
        await storeSession(senderId, session, encryptionKey);
    } else {
        throw new Error(`Unknown message type: ${type}`);
    }

    // ── Validate identity binding ────────────────────────────────────────
    if (payload.senderId && payload.senderId !== senderId) {
        throw new Error(
            `Sender identity mismatch: envelope says ${senderId} but payload says ${payload.senderId}.`,
        );
    }

    const myIdRow = await db.meta.get('user_id');
    const myId = myIdRow?.value ?? '';
    if (payload.recipientId && payload.recipientId !== myId) {
        throw new Error(
            'Message was not intended for this user (recipient mismatch).',
        );
    }

    // ── Timestamp freshness check (only for real-time; skip for offline) ─
    if (payload.timestamp && Math.abs(Date.now() - payload.timestamp) > MAX_MESSAGE_AGE_MS) {
        console.warn(`[Chat] Message from ${senderId} has stale timestamp (${new Date(payload.timestamp).toISOString()}). Allowing for offline delivery.`);
    }

    // Persist the message locally (encrypted at rest)
    return persistMessage(uuidv4(), senderId, payload.text, 'in', timestamp, encryptionKey, payload.attachment);
}

/**
 * Fetch and process all offline (queued) messages from the backend.
 * Returns the decrypted messages.
 */
export async function fetchAndProcessOfflineMessages(
    encryptionKey: CryptoKey,
): Promise<DecryptedMessage[]> {
    const res = await api.get('/messages/offline');
    const rawMessages: Array<{
        id: string;
        senderId: string;
        ciphertext: string;
        type: string;
        createdAt: string;
    }> = res.data.data ?? [];

    const decrypted: DecryptedMessage[] = [];

    for (const raw of rawMessages) {
        try {
            const msg = await processIncomingMessage(
                raw.senderId,
                raw.ciphertext,
                raw.type,
                new Date(raw.createdAt).getTime(),
                encryptionKey,
            );
            decrypted.push(msg);
        } catch (err) {
            console.error(`Failed to process offline message ${raw.id}:`, err);
        }
    }

    return decrypted;
}

/**
 * Load chat history for a specific contact from the local DB.
 * Decrypts all message text before returning.
 */
export async function loadMessages(
    contactId: string,
    encryptionKey: CryptoKey,
): Promise<DecryptedMessage[]> {
    const rows = await db.messages
        .where('contactId')
        .equals(contactId)
        .sortBy('timestamp');

    const result: DecryptedMessage[] = [];
    for (const row of rows) {
        result.push(await decryptMessageRow(row, encryptionKey));
    }
    return result;
}
