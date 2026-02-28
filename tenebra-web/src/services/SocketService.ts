/**
 * SocketService — Socket.io client wrapper for Tenebra real-time messaging.
 *
 * Connects to the backend Socket.io server using the JWT stored by the
 * API client.  Exposes an event-driven interface so the UI can react
 * to incoming messages without polling.
 *
 * Usage:
 *   const socket = connectSocket();
 *   onNewMessage((payload) => { … });
 *   // later:
 *   disconnectSocket();
 */

import { io, Socket } from 'socket.io-client';
import { getToken } from '@/api/client';

// ─── Types ─────────────────────────────────────────────────────────────────────

export interface IncomingMessagePayload {
    senderId: string;
    ciphertext: string;
    type: string;
    timestamp: string; // ISO-8601
}

type MessageHandler = (payload: IncomingMessagePayload) => void;

// ─── State ─────────────────────────────────────────────────────────────────────

let socket: Socket | null = null;
const messageHandlers: Set<MessageHandler> = new Set();

// ─── Public API ────────────────────────────────────────────────────────────────

/**
 * Open a Socket.io connection to the backend using the current JWT.
 * If already connected the existing socket is returned.
 */
export function connectSocket(): Socket {
    if (socket?.connected) return socket;

    const token = getToken();
    if (!token) throw new Error('Cannot connect socket: no JWT token available.');

    socket = io('/', {
        auth: { token },
        transports: ['websocket', 'polling'],
        reconnectionAttempts: 10,
        reconnectionDelay: 2_000,
    });

    socket.on('connect', () => {
        console.log('[Socket] Connected:', socket?.id);
    });

    socket.on('disconnect', (reason) => {
        console.log('[Socket] Disconnected:', reason);
    });

    socket.on('connect_error', (err) => {
        console.error('[Socket] Connection error:', err.message);
    });

    socket.on('new_message', (payload: IncomingMessagePayload) => {
        for (const handler of messageHandlers) {
            try {
                handler(payload);
            } catch (err) {
                console.error('[Socket] Handler error:', err);
            }
        }
    });

    return socket;
}

/**
 * Register a handler for incoming `new_message` events.
 * Returns an unsubscribe function.
 */
export function onNewMessage(handler: MessageHandler): () => void {
    messageHandlers.add(handler);
    return () => {
        messageHandlers.delete(handler);
    };
}

/**
 * Gracefully disconnect the socket and remove all handlers.
 */
export function disconnectSocket(): void {
    if (socket) {
        socket.disconnect();
        socket = null;
    }
    messageHandlers.clear();
}

/** Check if the socket is currently connected. */
export function isConnected(): boolean {
    return socket?.connected ?? false;
}
