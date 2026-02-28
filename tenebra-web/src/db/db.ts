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

/** Persisted chat message. */
export interface Message {
  /** Message UUID (primary key). */
  id: string;
  /** Remote user's UUID (indexed for conversation queries). */
  contactId: string;
  /** Decrypted plaintext. */
  text: string;
  /** 'in' = received, 'out' = sent. */
  direction: 'in' | 'out';
  /** Unix epoch milliseconds. */
  timestamp: number;
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
  }
}

/** Singleton database instance. */
export const db = new TenebraDB();
