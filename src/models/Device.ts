import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class Device extends BaseModel {
  static tableName = 'devices';

  declare id: string;
  user_id!: string;
  device_id!: number;
  identity_public_key!: string;
  registration_id!: number;
  device_name?: string;
  last_seen_at!: Date;
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
            from: 'devices.user_id',
            to: 'users.id',
          },
        },
      };
    };
  }

  // Static query methods
  static async findByUserId(userId: string): Promise<Device[]> {
    return this.query().where({ user_id: userId });
  }

  static async findByUserIdAndDeviceId(
    userId: string,
    deviceId: number
  ): Promise<Device | undefined> {
    return this.query().findOne({ user_id: userId, device_id: deviceId });
  }

  static async updateLastSeen(id: string): Promise<Device | undefined> {
    return this.query().patchAndFetchById(id, {
      last_seen_at: new Date(),
    });
  }
}
