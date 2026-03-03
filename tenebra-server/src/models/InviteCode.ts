import { BaseModel } from './BaseModel';

export class InviteCode extends BaseModel {
    static tableName = 'invite_codes';

    declare id: string;
    code!: string;
    is_used!: boolean;
    used_by!: string | null;
    declare created_at: Date;

    static async findValidCode(code: string): Promise<InviteCode | undefined> {
        return this.query().findOne({ code, is_used: false });
    }

    static async markUsed(id: string, userId: string): Promise<void> {
        await this.query().findById(id).patch({ is_used: true, used_by: userId });
    }
}
