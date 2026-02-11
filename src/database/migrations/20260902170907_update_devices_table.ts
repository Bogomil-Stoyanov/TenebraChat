import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  await knex.schema.alterTable('devices', (table) => {
    // Change device_id from integer to string for client-generated UUIDs
    table.string('fcm_token', 512).nullable();
  });

  // Convert device_id column from integer to string
  await knex.raw(`
    ALTER TABLE devices
    ALTER COLUMN device_id TYPE VARCHAR(255)
    USING device_id::VARCHAR(255)
  `);
}

export async function down(knex: Knex): Promise<void> {
  await knex.raw(`
    ALTER TABLE devices
    ALTER COLUMN device_id TYPE INTEGER
    USING device_id::INTEGER
  `);

  await knex.schema.alterTable('devices', (table) => {
    table.dropColumn('fcm_token');
  });
}
