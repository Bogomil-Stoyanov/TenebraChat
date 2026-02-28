import Dexie, { type Table } from 'dexie';

// ─── Schema Interfaces ────────────────────────────────────────────────────────

/** Local identity key pair — private key is always stored encrypted. */
export interface Identity {
  /** Primary key (always `'self'` for the local device identity). */
  id: string;
  /** Signal Protocol registration ID. */
  registrationId: number;
  /** Base64-encoded public identity key. */
  publicKey: string;
  /** AES-GCM encrypted private key (Base64 cipherText). */
  encryptedPrivateKey: string;
  /** AES-GCM IV used to encrypt the private key (Base64). */
  encryptedPrivateKeyIv: string;
}

/** One-time pre-key — private key is stored encrypted. */
export interface PreKey {
  /** Pre-key ID (auto-incrementing or assigned). */
  keyId: number;
  /** Base64-encoded public pre-key. */
  publicKey: string;
  /** AES-GCM encrypted private key (Base64 cipherText). */
  encryptedPrivateKey: string;
  /** AES-GCM IV (Base64). */
  encryptedPrivateKeyIv: string;
}

/** Signed pre-key — private key is stored encrypted. */
export interface SignedPreKey {
  /** Signed pre-key ID. */
  keyId: number;
  /** Base64-encoded public signed pre-key. */
  publicKey: string;
  /** AES-GCM encrypted private key (Base64 cipherText). */
  encryptedPrivateKey: string;
  /** AES-GCM IV (Base64). */
  encryptedPrivateKeyIv: string;
  /** Ed25519 signature over the public key (Base64). */
  signature: string;
}

/** Encrypted session record with a remote peer. */
export interface Session {
  /** `<userId>.<deviceId>` composite key. */
  id: string;
  /** AES-GCM encrypted session record (Base64 cipherText). */
  encryptedRecord: string;
  /** AES-GCM IV (Base64). */
  encryptedRecordIv: string;
}

/** Metadata row used to persist the encryption salt. */
export interface Meta {
  key: string;
  value: string;
}

/** Known contact (remote peer). */
export interface Contact {
  /** Remote user's UUID (primary key). */
  userId: string;
  /** Display username. */
  username: string;
}

/** Attachment metadata stored alongside a message (encrypted at rest). */
export interface AttachmentMeta {
  /** Backend file URL / path. */
  url: string;
  /** Base64 raw AES-GCM-256 file key (encrypted inside the E2EE payload). */
  keyBase64: string;
  /** Base64 12-byte IV used when encrypting the file. */
  ivBase64: string;
  /** Original MIME type (e.g. `image/png`). */
  mimeType: string;
  /** Original file name. */
  name: string;
}

/** Persisted chat message — text is always encrypted at rest. */
export interface Message {
  /** Message UUID (primary key). */
  id: string;
  /** Remote user's UUID (indexed for conversation queries). */
  contactId: string;
  /** AES-GCM encrypted message text (Base64 cipherText). */
  encryptedText: string;
  /** AES-GCM IV used to encrypt the text (Base64). */
  encryptedTextIv: string;
  /** 'in' = received, 'out' = sent. */
  direction: 'in' | 'out';
  /** Unix epoch milliseconds. */
  timestamp: number;
  /** AES-GCM encrypted attachment JSON (Base64), or undefined. */
  encryptedAttachment?: string;
  /** AES-GCM IV for the attachment field (Base64). */
  encryptedAttachmentIv?: string;
}

/** In-memory decrypted message for UI consumption. */
export interface DecryptedMessage {
  id: string;
  contactId: string;
  text: string;
  direction: 'in' | 'out';
  timestamp: number;
  /** Decrypted attachment metadata (if this message carries a file). */
  attachment?: AttachmentMeta;
}

// ─── Database ──────────────────────────────────────────────────────────────────

class TenebraDB extends Dexie {
  identity!: Table<Identity, string>;
  preKeys!: Table<PreKey, number>;
  signedPreKeys!: Table<SignedPreKey, number>;
  sessions!: Table<Session, string>;
  meta!: Table<Meta, string>;
  contacts!: Table<Contact, string>;
  messages!: Table<Message, string>;

  constructor() {
    super('tenebra');

    this.version(1).stores({
      identity: 'id',
      preKeys: 'keyId',
      signedPreKeys: 'keyId',
      sessions: 'id',
      meta: 'key',
    });

    this.version(2).stores({
      identity: 'id',
      preKeys: 'keyId',
      signedPreKeys: 'keyId',
      sessions: 'id',
      meta: 'key',
      contacts: 'userId',
      messages: 'id, contactId, timestamp',
    });

    // v3: attachment columns (non-indexed, just persisted)
    this.version(3).stores({
      identity: 'id',
      preKeys: 'keyId',
      signedPreKeys: 'keyId',
      sessions: 'id',
      meta: 'key',
      contacts: 'userId',
      messages: 'id, contactId, timestamp',
    });
  }
}

/** Singleton database instance. */
export const db = new TenebraDB();
