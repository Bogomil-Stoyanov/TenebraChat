import { Router, Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { Device } from '../models';
import { config } from '../config';
import { ApiResponse } from '../types';

const router = Router();

/**
 * GET /api/push/vapid-public-key
 *
 * Return the server's VAPID public key so the frontend can subscribe to push.
 */
router.get('/vapid-public-key', (_req: AuthenticatedRequest, res: Response): void => {
    if (!config.vapid.publicKey) {
        res.status(503).json({
            success: false,
            error: 'Push notifications are not configured',
        } as ApiResponse);
        return;
    }

    res.json({
        success: true,
        data: { vapidPublicKey: config.vapid.publicKey },
    } as ApiResponse);
});

/**
 * POST /api/push/subscribe
 *
 * Save the client's PushSubscription against their current device row.
 *
 * @body {object} subscription — The browser's PushSubscription JSON.
 */
router.post('/subscribe', async (req: AuthenticatedRequest, res: Response): Promise<void> => {
    try {
        if (!req.user) {
            res.status(401).json({ success: false, error: 'Not authenticated' } as ApiResponse);
            return;
        }

        const { subscription } = req.body;

        if (
            !subscription ||
            typeof subscription !== 'object' ||
            typeof subscription.endpoint !== 'string'
        ) {
            res.status(400).json({
                success: false,
                error: 'Missing or invalid subscription object',
            } as ApiResponse);
            return;
        }

        // Look up the device using the JWT deviceId
        const device = await Device.findByUserIdAndDeviceId(req.user.userId, req.user.deviceId);
        if (!device) {
            res.status(404).json({ success: false, error: 'Device not found' } as ApiResponse);
            return;
        }

        await Device.updatePushSubscription(device.id, JSON.stringify(subscription));

        res.json({
            success: true,
            message: 'Push subscription saved',
        } as ApiResponse);
    } catch (error) {
        console.error('[Push] Error saving subscription:', error);
        res.status(500).json({ success: false, error: 'Internal server error' } as ApiResponse);
    }
});

export default router;
