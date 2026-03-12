import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (table) => {
    table.text('push_subscription').nullable();
  });
}

export async function down(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (table) => {
    table.dropColumn('push_subscription');
  });
}
