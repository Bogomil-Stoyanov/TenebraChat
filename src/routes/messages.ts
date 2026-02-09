import { Router, Request, Response } from 'express';
import { QueuedMessage } from '../models';
import { ApiResponse } from '../types';

const router = Router();

// Queue a message for offline delivery
router.post('/queue', async (req: Request, res: Response) => {
    try {
        const { recipient_id, sender_id, encrypted_payload, message_type, file_reference } = req.body;

        if (!recipient_id || !sender_id || !encrypted_payload) {
            const response: ApiResponse = {
                success: false,
                error: 'Missing required fields: recipient_id, sender_id, encrypted_payload',
            };
            return res.status(400).json(response);
        }

        // Convert base64 payload to Buffer
        let payloadBuffer: Buffer;
        try {
            payloadBuffer = Buffer.from(encrypted_payload, 'base64');
        } catch {
            const response: ApiResponse = {
                success: false,
                error: 'Invalid encrypted_payload: must be base64 encoded',
            };
            return res.status(400).json(response);
        }

        const message = await QueuedMessage.query().insertAndFetch({
            recipient_id,
            sender_id,
            encrypted_payload: payloadBuffer,
            message_type: message_type || 'signal_message',
            file_reference,
        });

        const response: ApiResponse<{ id: string; created_at: Date }> = {
            success: true,
            data: {
                id: message.id,
                created_at: message.created_at,
            },
            message: 'Message queued successfully',
        };
        return res.status(201).json(response);
    } catch (error) {
        console.error('Error queuing message:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Fetch and delete queued messages for a user
router.post('/fetch/:userId', async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const { limit = 100 } = req.body;

        const messages = await QueuedMessage.fetchAndDelete(userId, limit);

        // Convert binary payloads to base64 for transport
        const messagesForTransport = messages.map(msg => ({
            id: msg.id,
            sender_id: msg.sender_id,
            encrypted_payload: msg.encrypted_payload.toString('base64'),
            message_type: msg.message_type,
            file_reference: msg.file_reference,
            created_at: msg.created_at,
        }));

        const response: ApiResponse<typeof messagesForTransport> = {
            success: true,
            data: messagesForTransport,
            message: `${messages.length} messages retrieved`,
        };
        return res.json(response);
    } catch (error) {
        console.error('Error fetching messages:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Peek at queued messages without deleting
router.get('/peek/:userId', async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const messages = await QueuedMessage.findByRecipientId(userId);

        // Convert binary payloads to base64 for transport
        const messagesForTransport = messages.map(msg => ({
            id: msg.id,
            sender_id: msg.sender_id,
            encrypted_payload: msg.encrypted_payload.toString('base64'),
            message_type: msg.message_type,
            file_reference: msg.file_reference,
            created_at: msg.created_at,
        }));

        const response: ApiResponse<typeof messagesForTransport> = {
            success: true,
            data: messagesForTransport,
        };
        return res.json(response);
    } catch (error) {
        console.error('Error peeking messages:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Get message count for a user
router.get('/count/:userId', async (req: Request, res: Response) => {
    try {
        const { userId } = req.params;
        const count = await QueuedMessage.countByRecipientId(userId);

        const response: ApiResponse<{ count: number }> = {
            success: true,
            data: { count },
        };
        return res.json(response);
    } catch (error) {
        console.error('Error counting messages:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Delete specific messages by IDs
router.delete('/batch', async (req: Request, res: Response) => {
    try {
        const { message_ids }: { message_ids: string[] } = req.body;

        if (!message_ids || !Array.isArray(message_ids) || message_ids.length === 0) {
            const response: ApiResponse = {
                success: false,
                error: 'Missing required field: message_ids (array)',
            };
            return res.status(400).json(response);
        }

        const deleted = await QueuedMessage.deleteByIds(message_ids);

        const response: ApiResponse<{ deleted: number }> = {
            success: true,
            data: { deleted },
            message: `${deleted} messages deleted`,
        };
        return res.json(response);
    } catch (error) {
        console.error('Error deleting messages:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Admin endpoint: cleanup expired messages
router.post('/cleanup', async (req: Request, res: Response) => {
    try {
        const deleted = await QueuedMessage.cleanupExpired();

        const response: ApiResponse<{ deleted: number }> = {
            success: true,
            data: { deleted },
            message: `${deleted} expired messages cleaned up`,
        };
        return res.json(response);
    } catch (error) {
        console.error('Error cleaning up messages:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

// Admin endpoint: get queue stats
router.get('/stats', async (req: Request, res: Response) => {
    try {
        const stats = await QueuedMessage.getQueueStats();

        const response: ApiResponse<typeof stats> = {
            success: true,
            data: stats,
        };
        return res.json(response);
    } catch (error) {
        console.error('Error getting queue stats:', error);
        const response: ApiResponse = {
            success: false,
            error: 'Internal server error',
        };
        return res.status(500).json(response);
    }
});

export default router;
