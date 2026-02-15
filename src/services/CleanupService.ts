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

  /**
   * Register and start all cron jobs.
   * Safe to call once at server startup.
   */
  start(): void {
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

    // Job 2: Purge stale queued messages daily at 03:00
    this.tasks.push(
      cron.schedule('0 3 * * *', async () => {
        try {
          const cutoff = new Date();
          cutoff.setDate(cutoff.getDate() - MESSAGE_RETENTION_DAYS);

          const deleted = await QueuedMessage.query().where('created_at', '<', cutoff).delete();

          if (deleted > 0) {
            console.log(
              `[CleanupService] Purged ${deleted} queued message(s) older than ${MESSAGE_RETENTION_DAYS} days`
            );
          }
        } catch (error) {
          console.error('[CleanupService] Failed to purge stale queued messages:', error);
        }
      })
    );

    console.log('CleanupService started (auth challenges: every 10 min, stale messages: daily)');
  }

  /**
   * Gracefully stop all scheduled tasks (useful for tests or shutdown).
   */
  stop(): void {
    for (const task of this.tasks) {
      task.stop();
    }
    this.tasks = [];
    console.log('[CleanupService] All scheduled tasks stopped');
  }
}

/** Singleton instance for use across the application. */
export const cleanupService = new CleanupService();
