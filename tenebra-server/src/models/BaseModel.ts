import { Model, QueryContext } from 'objection';

export class BaseModel extends Model {
  id!: string;
  created_at!: Date;

  static get modelPaths() {
    return [__dirname];
  }

  $beforeInsert(_queryContext: QueryContext) {
    if (!this.created_at) {
      this.created_at = new Date();
    }
  }
}
