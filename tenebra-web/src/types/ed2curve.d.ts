declare module 'ed2curve' {
    /**
     * Convert an Ed25519 public key (32 bytes) to a Curve25519 / X25519
     * public key (32 bytes).  Returns `null` if the conversion fails.
     */
    export function convertPublicKey(ed25519PublicKey: Uint8Array): Uint8Array | null;

    /**
     * Convert a 64-byte Ed25519 secret key (seed ‖ publicKey) to a
     * 32-byte Curve25519 / X25519 private scalar.
     */
    export function convertSecretKey(ed25519SecretKey: Uint8Array): Uint8Array;
}
