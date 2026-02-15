import cron, { ScheduledTask } from 'node-cron';
import { AuthChallenge, QueuedMessage } from '../models';

/** Number of days after which queued messages are considered stale. */
const MESSAGE_RETENTION_DAYS = 30;

/**
 * Centralized cleanup service that schedules periodic maintenance tasks
 * using `node-cron`.
 *
 * Jobs:
 * 1. Every 10 minutes — purge expired `auth_challenges`.
 * 2. Daily at 03:00 — purge `message_queue` rows older than 30 days.
 */
export class CleanupService {
  private tasks: ScheduledTask[] = [];
  private started = false;

  /**
   * Register and start all cron jobs.
   * Idempotent — calling more than once is a no-op.
   */
  start(): void {
    if (this.started) {
      console.warn('[CleanupService] Already started — skipping duplicate initialisation');
      return;
    }

    // Job 1: Purge expired auth challenges every 10 minutes
    this.tasks.push(
      cron.schedule('*/10 * * * *', async () => {
        try {
          const deleted = await AuthChallenge.cleanupExpired();
          if (deleted > 0) {
            console.log(`[CleanupService] Purged ${deleted} expired auth challenge(s)`);
          }
        } catch (error) {
          console.error('[CleanupService] Failed to purge expired auth challenges:', error);
        }
      })
    );

    // Job 2: Purge stale queued messages daily at 03:00 UTC
    this.tasks.push(
      cron.schedule(
        '0 3 * * *',
        async () => {
          try {
            // 2a — Remove messages whose expires_at has passed
            const expiredCount = await QueuedMessage.cleanupExpired();

            // 2b — Remove messages older than the retention window
            const cutoff = new Date();
            cutoff.setDate(cutoff.getDate() - MESSAGE_RETENTION_DAYS);
            const staleCount = await QueuedMessage.query()
              .where('created_at', '<', cutoff)
              .delete();

            const total = expiredCount + staleCount;
            if (total > 0) {
              console.log(
                `[CleanupService] Purged ${total} queued message(s) ` +
                  `(${expiredCount} expired, ${staleCount} older than ${MESSAGE_RETENTION_DAYS}d)`
              );
            }
          } catch (error) {
            console.error('[CleanupService] Failed to purge stale queued messages:', error);
          }
        },
        { timezone: 'UTC' }
      )
    );

    this.started = true;
    console.log(
      'CleanupService started (auth challenges: every 10 min, stale messages: daily 03:00 UTC)'
    );
  }

  /**
   * Gracefully stop all scheduled tasks (useful for tests or shutdown).
   */
  stop(): void {
    for (const task of this.tasks) {
      task.stop();
    }
    this.tasks = [];
    this.started = false;
    console.log('[CleanupService] All scheduled tasks stopped');
  }
}

/** Singleton instance for use across the application. */
export const cleanupService = new CleanupService();
