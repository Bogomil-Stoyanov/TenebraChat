import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class Device extends BaseModel {
  static tableName = 'devices';

  declare id: string;
  user_id!: string;
  device_id!: string;
  identity_public_key!: string;
  registration_id!: number;
  device_name?: string;
  fcm_token?: string | null;
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
    deviceId: string
  ): Promise<Device | undefined> {
    return this.query().findOne({ user_id: userId, device_id: deviceId });
  }

  static async upsertDevice(
    userId: string,
    deviceId: string,
    identityPublicKey: string,
    registrationId: number,
    fcmToken?: string
  ): Promise<Device> {
    // Delete all other devices for this user (single session enforcement)
    await this.query().where({ user_id: userId }).delete();

    // Insert the new/current device
    return this.query().insertAndFetch({
      user_id: userId,
      device_id: deviceId,
      identity_public_key: identityPublicKey,
      registration_id: registrationId,
      fcm_token: fcmToken || null,
      last_seen_at: new Date(),
    });
  }

  static async deleteByUserIdAndDeviceId(userId: string, deviceId: string): Promise<number> {
    return this.query().where({ user_id: userId, device_id: deviceId }).delete();
  }

  static async deleteAllByUserId(userId: string): Promise<number> {
    return this.query().where({ user_id: userId }).delete();
  }

  static async updateLastSeen(id: string): Promise<Device | undefined> {
    return this.query().patchAndFetchById(id, {
      last_seen_at: new Date(),
    });
  }

  static async updateFcmToken(
    userId: string,
    deviceId: string,
    fcmToken: string
  ): Promise<Device | undefined> {
    const device = await this.findByUserIdAndDeviceId(userId, deviceId);
    if (!device) return undefined;
    return this.query().patchAndFetchById(device.id, { fcm_token: fcmToken });
  }
}
