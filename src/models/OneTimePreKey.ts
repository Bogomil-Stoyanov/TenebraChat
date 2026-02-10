import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class OneTimePreKey extends BaseModel {
  static tableName = 'one_time_pre_keys';

  declare id: string;
  user_id!: string;
  key_id!: number;
  public_key!: string;
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
            from: 'one_time_pre_keys.user_id',
            to: 'users.id',
          },
        },
      };
    };
  }

  // Static query methods
  static async countByUserId(userId: string): Promise<number> {
    const result = await this.query().where({ user_id: userId }).count('id as count').first();
    return parseInt((result as any)?.count || '0', 10);
  }

  static async consumeOne(userId: string): Promise<OneTimePreKey | undefined> {
    // Get the oldest one-time pre-key
    const key = await this.query().where({ user_id: userId }).orderBy('created_at', 'asc').first();

    if (!key) return undefined;

    // Delete it
    await this.query().deleteById(key.id);

    return key;
  }

  static async createBatch(
    keys: Array<{ user_id: string; key_id: number; public_key: string }>
  ): Promise<OneTimePreKey[]> {
    if (keys.length === 0) return [];
    return this.query().insertAndFetch(keys);
  }
}
