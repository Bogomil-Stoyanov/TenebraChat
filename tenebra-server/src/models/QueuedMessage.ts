import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class QueuedMessage extends BaseModel {
  static tableName = 'message_queue';

  declare id: string;
  recipient_id!: string;
  sender_id!: string;
  encrypted_payload!: Buffer;
  message_type!: string;
  file_reference?: string;
  declare created_at: Date;
  expires_at!: Date;

  // Relations
  recipient?: import('./User').User;
  sender?: import('./User').User;

  static get relationMappings(): RelationMappingsThunk {
    return () => {
      const { User } = require('./User');

      return {
        recipient: {
          relation: Model.BelongsToOneRelation,
          modelClass: User,
          join: {
            from: 'message_queue.recipient_id',
            to: 'users.id',
          },
        },
        sender: {
          relation: Model.BelongsToOneRelation,
          modelClass: User,
          join: {
            from: 'message_queue.sender_id',
            to: 'users.id',
          },
        },
      };
    };
  }

  // Static query methods
  static async findByRecipientId(recipientId: string): Promise<QueuedMessage[]> {
    return this.query().where({ recipient_id: recipientId }).orderBy('created_at', 'asc');
  }

  static async countByRecipientId(recipientId: string): Promise<number> {
    const result = await this.query()
      .where({ recipient_id: recipientId })
      .count('id as count')
      .first();
    return parseInt((result as any)?.count || '0', 10);
  }

  static async fetchAndDelete(recipientId: string, limit: number = 100): Promise<QueuedMessage[]> {
    return this.transaction(async (trx) => {
      // Lock selected rows to prevent duplicate delivery
      const messages = await this.query(trx)
        .where({ recipient_id: recipientId })
        .orderBy('created_at', 'asc')
        .limit(limit)
        .forUpdate();

      if (messages.length === 0) return [];

      const ids = messages.map((m) => m.id);
      await this.query(trx).whereIn('id', ids).delete();

      return messages;
    });
  }

  static async deleteByIds(ids: string[]): Promise<number> {
    if (ids.length === 0) return 0;
    return this.query().whereIn('id', ids).delete();
  }

  static async cleanupExpired(): Promise<number> {
    return this.query().where('expires_at', '<', new Date()).delete();
  }

  static async getQueueStats(): Promise<{ total: number; oldest: Date | null }> {
    const totalResult = await this.query().count('id as count').first();
    const oldestResult = await this.query().min('created_at as oldest').first();

    return {
      total: parseInt((totalResult as any)?.count || '0', 10),
      oldest: (oldestResult as any)?.oldest || null,
    };
  }
}
