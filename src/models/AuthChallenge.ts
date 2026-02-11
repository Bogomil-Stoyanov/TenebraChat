import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class AuthChallenge extends BaseModel {
  static tableName = 'auth_challenges';

  declare id: string;
  user_id!: string;
  nonce!: string;
  expires_at!: Date;
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
            from: 'auth_challenges.user_id',
            to: 'users.id',
          },
        },
      };
    };
  }

  get isExpired(): boolean {
    return new Date() > new Date(this.expires_at);
  }

  static async createForUser(
    userId: string,
    nonce: string,
    expiresInMs = 2 * 60 * 1000
  ): Promise<AuthChallenge> {
    // Delete any existing challenges for this user
    await this.query().where({ user_id: userId }).delete();

    const expiresAt = new Date(Date.now() + expiresInMs);

    return this.query().insertAndFetch({
      user_id: userId,
      nonce,
      expires_at: expiresAt,
    });
  }

  static async findActiveByUserId(userId: string): Promise<AuthChallenge | undefined> {
    return this.query()
      .where({ user_id: userId })
      .where('expires_at', '>', new Date())
      .orderBy('created_at', 'desc')
      .first();
  }

  static async deleteByUserId(userId: string): Promise<number> {
    return this.query().where({ user_id: userId }).delete();
  }

  static async cleanupExpired(): Promise<number> {
    return this.query().where('expires_at', '<', new Date()).delete();
  }
}
