import type { Knex } from 'knex';

/**
 * Create the `seen_message_hashes` table for server-side replay protection.
 *
 * Stores SHA-256 hex digests of every ciphertext blob that passes through
 * the messaging endpoint.  A UNIQUE constraint on `hash` rejects any
 * duplicate ciphertext, preventing replay attacks.
 *
 * Rows older than a configurable TTL are periodically purged by the
 * CleanupService.
 */
export async function up(knex: Knex): Promise<void> {
    await knex.schema.createTable('seen_message_hashes', (table) => {
        table
            .string('hash', 64)
            .primary()
            .notNullable()
            .comment('SHA-256 hex digest of the ciphertext');
        table
            .timestamp('created_at', { useTz: true })
            .defaultTo(knex.fn.now())
            .notNullable();
    });
}

export async function down(knex: Knex): Promise<void> {
    await knex.schema.dropTableIfExists('seen_message_hashes');
}
