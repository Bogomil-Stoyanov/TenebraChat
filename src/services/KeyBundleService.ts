import { User, SignedPreKey, OneTimePreKey } from '../models';
import { PreKeyBundle } from '../types';

export class KeyBundleService {
    /**
     * Fetches a pre-key bundle for establishing an X3DH session with a user.
     * This consumes one one-time pre-key if available.
     */
    static async getPreKeyBundle(userId: string): Promise<PreKeyBundle | null> {
        const user = await User.query().findById(userId);
        if (!user) {
            return null;
        }

        const signedPreKey = await SignedPreKey.findLatestByUserId(userId);
        if (!signedPreKey) {
            return null;
        }

        // Consume one one-time pre-key (if available)
        const oneTimePreKey = await OneTimePreKey.consumeOne(userId);

        const bundle: PreKeyBundle = {
            user_id: user.id,
            username: user.username,
            registration_id: user.registration_id,
            identity_public_key: user.identity_public_key,
            signed_pre_key: {
                key_id: signedPreKey.key_id,
                public_key: signedPreKey.public_key,
                signature: signedPreKey.signature,
            },
        };

        if (oneTimePreKey) {
            bundle.one_time_pre_key = {
                key_id: oneTimePreKey.key_id,
                public_key: oneTimePreKey.public_key,
            };
        }

        return bundle;
    }

    /**
     * Gets the count of remaining one-time pre-keys for a user.
     * Clients should upload more keys when this count is low.
     */
    static async getOneTimePreKeyCount(userId: string): Promise<number> {
        return OneTimePreKey.countByUserId(userId);
    }

    /**
     * Checks if a user needs to upload more one-time pre-keys.
     * Returns true if count is below threshold.
     */
    static async needsMorePreKeys(userId: string, threshold: number = 10): Promise<boolean> {
        const count = await this.getOneTimePreKeyCount(userId);
        return count < threshold;
    }
}
