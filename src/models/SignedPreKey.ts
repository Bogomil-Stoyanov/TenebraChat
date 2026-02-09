import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class SignedPreKey extends BaseModel {
    static tableName = 'signed_pre_keys';

    declare id: string;
    user_id!: string;
    key_id!: number;
    public_key!: string;
    signature!: string;
    declare created_at: Date;

    // Relations
    user?: import('./User').User;

    static get relationMappings(): RelationMappingsThunk {
        return () => {
            const { User } = require('./User');

            return {
                user: {
                    relation: Model.BelongsToOneRelation,
                    modelClass: User,
                    join: {
                        from: 'signed_pre_keys.user_id',
                        to: 'users.id',
                    },
                },
            };
        };
    }

    // Static query methods
    static async findLatestByUserId(userId: string): Promise<SignedPreKey | undefined> {
        return this.query()
            .where({ user_id: userId })
            .orderBy('created_at', 'desc')
            .first();
    }

    static async findByUserIdAndKeyId(userId: string, keyId: number): Promise<SignedPreKey | undefined> {
        return this.query().findOne({ user_id: userId, key_id: keyId });
    }

    static async upsert(data: {
        user_id: string;
        key_id: number;
        public_key: string;
        signature: string;
    }): Promise<SignedPreKey> {
        const existing = await this.findByUserIdAndKeyId(data.user_id, data.key_id);

        if (existing) {
            return this.query()
                .patchAndFetchById(existing.id, {
                    public_key: data.public_key,
                    signature: data.signature,
                });
        }

        return this.query().insertAndFetch(data);
    }

    static async deleteOldKeys(userId: string, keepLatest: number = 5): Promise<number> {
        const keysToKeep = await this.query()
            .where({ user_id: userId })
            .orderBy('created_at', 'desc')
            .limit(keepLatest)
            .select('id');

        const keepIds = keysToKeep.map(k => k.id);

        if (keepIds.length === 0) return 0;

        return this.query()
            .where({ user_id: userId })
            .whereNotIn('id', keepIds)
            .delete();
    }
}
