import { Server as HttpServer } from 'http';
import { Server, Socket } from 'socket.io';
import jwt from 'jsonwebtoken';
import { config } from './config';
import { Device } from './models';
import { JwtPayload } from './middleware/auth';

/**
 * In-memory map of connected clients.
 *
 * Key:   `${userId}:${deviceId}`
 * Value: Socket.io `socket.id`
 *
 * Tenebra enforces a single active connection per user:device combination.
 * Because the auth system also enforces one device per user, there will be
 * at most one entry per userId at any time.
 */
interface OnlineClient {
  userId: string;
  deviceId: string;
  socketId: string;
}

const onlineClients = new Map<string, OnlineClient>();

/** Reference to the Socket.io server instance. */
let io: Server;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/** Build a deterministic map key from userId + deviceId. */
function clientKey(userId: string, deviceId: string): string {
  return `${userId}:${deviceId}`;
}

/**
 * Verify a raw Bearer-style token and return the validated payload, or
 * `null` if verification fails for any reason.
 */
function verifyToken(token: string): JwtPayload | null {
  try {
    const decoded = jwt.verify(token, config.jwt.secret);

    if (
      typeof decoded !== 'object' ||
      decoded === null ||
      typeof (decoded as JwtPayload).userId !== 'string' ||
      typeof (decoded as JwtPayload).deviceId !== 'string'
    ) {
      return null;
    }

    return decoded as JwtPayload;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/**
 * Initialise Socket.io on the given HTTP server.
 *
 * - Registers a connection-level JWT authentication middleware.
 * - Tracks online clients in the `onlineClients` map.
 * - Cleans up on disconnect.
 */
export function initSocket(httpServer: HttpServer): Server {
  io = new Server(httpServer, {
    cors: {
      origin: '*', // TODO tighten in production
      methods: ['GET', 'POST'],
    },
  });

  // -----------------------------------------------------------------------
  // Socket.io authentication middleware
  // -----------------------------------------------------------------------
  io.use(async (socket: Socket, next) => {
    const token = socket.handshake.auth?.token as string | undefined;

    if (!token) {
      return next(
        new Error('Authentication required: provide a JWT token via socket.handshake.auth.token')
      );
    }

    const payload = verifyToken(token);
    if (!payload) {
      return next(new Error('Invalid or expired token'));
    }

    // Ensure the device still exists in the DB (remote-logout enforcement)
    const device = await Device.findByUserIdAndDeviceId(payload.userId, payload.deviceId);
    if (!device) {
      return next(new Error('Session invalidated'));
    }

    // Attach the validated payload to the socket for later use
    socket.data.user = payload;
    next();
  });

  // -----------------------------------------------------------------------
  // Connection handler
  // -----------------------------------------------------------------------
  io.on('connection', (socket: Socket) => {
    const user = socket.data.user as JwtPayload;
    const key = clientKey(user.userId, user.deviceId);

    // If there is an existing socket for this user:device, disconnect it
    const existingClient = onlineClients.get(key);
    if (existingClient) {
      const existing = io.sockets.sockets.get(existingClient.socketId);
      if (existing) {
        existing.disconnect(true);
      }
    }

    onlineClients.set(key, { userId: user.userId, deviceId: user.deviceId, socketId: socket.id });
    console.log(`Client connected: ${key} (socket ${socket.id})`);

    // Join a room named after the userId so we can target by user
    socket.join(user.userId);

    socket.on('disconnect', () => {
      // Only remove from the map if *this* socket is still the current one
      const current = onlineClients.get(key);
      if (current && current.socketId === socket.id) {
        onlineClients.delete(key);
        console.log(`Client disconnected: ${key} (socket ${socket.id})`);
      } else {
        console.log(
          `Stale socket disconnected for ${key} (socket ${socket.id}) — a newer socket is active`
        );
      }
    });
  });

  return io;
}

/**
 * Returns the Socket.io `Server` instance.
 * Throws if called before `initSocket()`.
 */
export function getIO(): Server {
  if (!io) {
    throw new Error('Socket.io has not been initialised — call initSocket() first.');
  }
  return io;
}

/**
 * Check whether a specific user:device is currently connected.
 */
export function isClientOnline(userId: string, deviceId: string): boolean {
  return onlineClients.has(clientKey(userId, deviceId));
}

/**
 * Get the socket ID for a connected user:device, or `undefined`.
 */
export function getClientSocketId(userId: string, deviceId: string): string | undefined {
  return onlineClients.get(clientKey(userId, deviceId))?.socketId;
}

/**
 * Find *any* online deviceId for a given userId (single-session model
 * means at most one).  Returns `undefined` if the user is offline.
 */
export function findOnlineDeviceForUser(
  userId: string
): { deviceId: string; socketId: string } | undefined {
  for (const [, client] of onlineClients.entries()) {
    if (client.userId === userId) {
      return { deviceId: client.deviceId, socketId: client.socketId };
    }
  }
  return undefined;
}
