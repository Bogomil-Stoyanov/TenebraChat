import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  return knex.schema.createTable('message_queue', (table) => {
    table.uuid('id').primary().defaultTo(knex.raw('uuid_generate_v4()'));
    table.uuid('recipient_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.uuid('sender_id').notNullable().references('id').inTable('users').onDelete('CASCADE');
    table.binary('encrypted_payload').notNullable();
    table.string('message_type', 50).notNullable().defaultTo('signal_message');
    table.text('file_reference');
    table.timestamp('created_at', { useTz: true }).defaultTo(knex.fn.now());
    table
      .timestamp('expires_at', { useTz: true })
      .defaultTo(knex.raw("CURRENT_TIMESTAMP + INTERVAL '30 days'"));

    table.index('recipient_id');
    table.index('expires_at');
    table.index(['recipient_id', 'created_at']);
  });
}

export async function down(knex: Knex): Promise<void> {
  return knex.schema.dropTableIfExists('message_queue');
}
