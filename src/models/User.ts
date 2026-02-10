import { Model, RelationMappingsThunk } from 'objection';
import { BaseModel } from './BaseModel';

export class User extends BaseModel {
  static tableName = 'users';

  declare id: string;
  username!: string;
  identity_public_key!: string;
  registration_id!: number;
  declare created_at: Date;
  updated_at!: Date;

  // Relations
  signedPreKeys?: import('./SignedPreKey').SignedPreKey[];
  oneTimePreKeys?: import('./OneTimePreKey').OneTimePreKey[];
  devices?: import('./Device').Device[];

  static get relationMappings(): RelationMappingsThunk {
    return () => {
      const { SignedPreKey } = require('./SignedPreKey');
      const { OneTimePreKey } = require('./OneTimePreKey');
      const { Device } = require('./Device');

      return {
        signedPreKeys: {
          relation: Model.HasManyRelation,
          modelClass: SignedPreKey,
          join: {
            from: 'users.id',
            to: 'signed_pre_keys.user_id',
          },
        },
        oneTimePreKeys: {
          relation: Model.HasManyRelation,
          modelClass: OneTimePreKey,
          join: {
            from: 'users.id',
            to: 'one_time_pre_keys.user_id',
          },
        },
        devices: {
          relation: Model.HasManyRelation,
          modelClass: Device,
          join: {
            from: 'users.id',
            to: 'devices.user_id',
          },
        },
      };
    };
  }

  $beforeUpdate() {
    this.updated_at = new Date();
  }

  // Static query methods
  static async findByUsername(username: string): Promise<User | undefined> {
    return this.query().findOne({ username });
  }

  static async findByIdWithKeys(id: string): Promise<User | undefined> {
    return this.query().findById(id).withGraphFetched('[signedPreKeys, oneTimePreKeys]');
  }
}
