import type { Knex } from 'knex';

export async function up(knex: Knex): Promise<void> {
  // Convert device_id column from integer to string first (critical schema change)
  await knex.raw(`
    ALTER TABLE devices
    ALTER COLUMN device_id TYPE VARCHAR(255)
    USING device_id::VARCHAR(255)
  `);

  // Add FCM token column for push notifications
  await knex.schema.alterTable('devices', (table) => {
    table.string('fcm_token', 512).nullable();
  });
}

export async function down(knex: Knex): Promise<void> {
  // Safely convert device_id back to integer — non-numeric values become NULL
  await knex.raw(`
    ALTER TABLE devices
    ALTER COLUMN device_id TYPE INTEGER
    USING (
      CASE
        WHEN device_id ~ '^[0-9]+$' THEN device_id::INTEGER
        ELSE NULL
      END
    )
  `);

  await knex.schema.alterTable('devices', (table) => {
    table.dropColumn('fcm_token');
  });
}
