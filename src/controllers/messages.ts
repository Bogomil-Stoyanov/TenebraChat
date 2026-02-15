import { Response } from 'express';
import { AuthenticatedRequest } from '../middleware/auth';
import { QueuedMessage, Device } from '../models';
import { ApiResponse } from '../types';
import { getIO, findOnlineDeviceForUser } from '../socket';

/** Maximum ciphertext size: 64 KB base64 ≈ ~48 KB raw. */
const MAX_CIPHERTEXT_LENGTH = 65_536;

/** Allowed message types for the Signal protocol. */
const ALLOWED_MESSAGE_TYPES = new Set(['signal_message', 'pre_key_signal_message', 'key_exchange']);

const UUID_RE = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

// ---------------------------------------------------------------------------
// Input validation helpers
// ---------------------------------------------------------------------------

interface SendMessageInput {
  recipientId: string;
  ciphertext: string;
  type: string;
}

/**
 * Validate and extract the fields from the send-message request body.
 * Returns a typed object on success or an error string on failure.
 */
function validateSendInput(body: Record<string, unknown>): SendMessageInput | string {
  const { recipientId, ciphertext, type } = body;

  if (
    typeof recipientId !== 'string' ||
    typeof ciphertext !== 'string' ||
    recipientId.trim().length === 0 ||
    ciphertext.trim().length === 0
  ) {
    return 'Missing required fields: recipientId, ciphertext';
  }

  if (ciphertext.length > MAX_CIPHERTEXT_LENGTH) {
    return `ciphertext exceeds maximum length of ${MAX_CIPHERTEXT_LENGTH} characters`;
  }

  // Validate base64 encoding
  if (!/^[A-Za-z0-9+/]*={0,2}$/.test(ciphertext)) {
    return 'ciphertext must be valid base64';
  }

  const messageType =
    typeof type === 'string' && type.trim().length > 0 ? type.trim() : 'signal_message';
  if (!ALLOWED_MESSAGE_TYPES.has(messageType)) {
    return `Invalid message type. Allowed: ${[...ALLOWED_MESSAGE_TYPES].join(', ')}`;
  }

  return {
    recipientId: recipientId.trim(),
    ciphertext,
    type: messageType,
  };
}

// ---------------------------------------------------------------------------
// Controllers
// ---------------------------------------------------------------------------

/**
 * POST /api/messages/send
 *
 * Send an encrypted message to a recipient.
 *
 * - If the recipient is **online** → emit `new_message` via Socket.io.
 * - If the recipient is **offline** → persist to the `message_queue` table.
 *
 * @body {string} recipientId - UUID of the recipient user.
 * @body {string} ciphertext  - Base64-encoded Signal ciphertext.
 * @body {string} [type]      - Message type (default `signal_message`).
 *
 * @returns {{ delivered: boolean; messageId?: string }}
 */
export async function sendMessage(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ success: false, error: 'Not authenticated' } as ApiResponse);
      return;
    }

    const result = validateSendInput(req.body);
    if (typeof result === 'string') {
      res.status(400).json({ success: false, error: result } as ApiResponse);
      return;
    }

    const { recipientId, ciphertext, type } = result;
    const senderId = req.user.userId;

    // Prevent sending messages to yourself
    if (recipientId === senderId) {
      res
        .status(400)
        .json({ success: false, error: 'Cannot send a message to yourself' } as ApiResponse);
      return;
    }

    // Verify recipient exists
    const recipientDevices = await Device.findByUserId(recipientId);
    if (recipientDevices.length === 0) {
      // No devices registered → user either doesn't exist or has never logged in
      res.status(404).json({
        success: false,
        error: 'Recipient not found or has no active device',
      } as ApiResponse);
      return;
    }

    // Check if recipient is online
    const online = findOnlineDeviceForUser(recipientId);

    if (online) {
      // --- ONLINE: deliver in real-time via Socket.io (with fallback to queue) ---
      const io = getIO();
      const socket = io.sockets.sockets.get(online.socketId);

      if (socket && socket.connected) {
        socket.emit('new_message', {
          senderId,
          ciphertext,
          type,
          timestamp: new Date().toISOString(),
        });

        const response: ApiResponse<{ delivered: boolean }> = {
          success: true,
          data: { delivered: true },
          message: 'Message delivered in real-time',
        };
        res.json(response);
        return;
      }

      // Socket is stale — fall through to offline queueing
    }

    // --- OFFLINE (or stale socket): persist to the message queue ---
    const payloadBuffer = Buffer.from(ciphertext, 'base64');

    const queued = await QueuedMessage.query().insertAndFetch({
      recipient_id: recipientId,
      sender_id: senderId,
      encrypted_payload: payloadBuffer,
      message_type: type,
    });

    const response: ApiResponse<{ delivered: boolean; messageId: string }> = {
      success: true,
      data: { delivered: false, messageId: queued.id },
      message: 'Recipient offline — message queued',
    };
    res.status(201).json(response);
  } catch (error) {
    console.error('Error sending message:', error);
    res.status(500).json({ success: false, error: 'Internal server error' } as ApiResponse);
  }
}

/**
 * GET /api/messages/offline
 *
 * Fetch and atomically delete all queued messages for the authenticated user.
 * The client should call this on connection to retrieve anything that arrived
 * while it was offline.
 *
 * @query {number} [limit=100] - Max messages to retrieve in one call.
 *
 * @returns {Array<{ id, senderId, ciphertext, type, createdAt }>}
 */
export async function fetchOfflineMessages(
  req: AuthenticatedRequest,
  res: Response
): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ success: false, error: 'Not authenticated' } as ApiResponse);
      return;
    }

    const limit = Math.min(Math.max(parseInt(req.query.limit as string, 10) || 100, 1), 100);

    const messages = await QueuedMessage.fetchAndDelete(req.user.userId, limit);

    const data = messages.map((msg) => ({
      id: msg.id,
      senderId: msg.sender_id,
      ciphertext: msg.encrypted_payload.toString('base64'),
      type: msg.message_type,
      fileReference: msg.file_reference || null,
      createdAt: msg.created_at,
    }));

    const response: ApiResponse<typeof data> = {
      success: true,
      data,
      message: `${data.length} message(s) retrieved`,
    };
    res.json(response);
  } catch (error) {
    console.error('Error fetching offline messages:', error);
    res.status(500).json({ success: false, error: 'Internal server error' } as ApiResponse);
  }
}

/**
 * DELETE /api/messages/batch
 *
 * Delete specific queued messages by their IDs (client-driven acknowledgement).
 *
 * @body {string[]} messageIds - Array of message UUIDs to delete.
 */
export async function deleteMessages(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      res.status(401).json({ success: false, error: 'Not authenticated' } as ApiResponse);
      return;
    }

    const { messageIds } = req.body;

    if (!Array.isArray(messageIds) || messageIds.length === 0) {
      res.status(400).json({
        success: false,
        error: 'Missing required field: messageIds (array)',
      } as ApiResponse);
      return;
    }

    if (messageIds.some((id) => typeof id !== 'string' || !UUID_RE.test(id))) {
      res.status(400).json({
        success: false,
        error: 'All messageIds must be valid UUIDs',
      } as ApiResponse);
      return;
    }

    // Only allow the authenticated user to delete their own messages
    const deleted = await QueuedMessage.query()
      .whereIn('id', messageIds)
      .andWhere({ recipient_id: req.user.userId })
      .delete();

    const response: ApiResponse<{ deleted: number }> = {
      success: true,
      data: { deleted },
      message: `${deleted} message(s) deleted`,
    };
    res.json(response);
  } catch (error) {
    console.error('Error deleting messages:', error);
    res.status(500).json({ success: false, error: 'Internal server error' } as ApiResponse);
  }
}
