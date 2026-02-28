import { Router } from 'express';
import { sendMessage, fetchOfflineMessages, deleteMessages } from '../controllers/messages';

const router = Router();

// POST /api/messages/send — Relay a message (real-time or queued)
router.post('/send', sendMessage);

// GET  /api/messages/offline — Fetch & delete queued offline messages
router.get('/offline', fetchOfflineMessages);

// DELETE /api/messages/batch — Client-driven ack / delete specific messages
router.delete('/batch', deleteMessages);

export default router;
