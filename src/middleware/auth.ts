import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { Device } from '../models';
import { ApiResponse } from '../types';

export interface JwtPayload {
  userId: string;
  deviceId: string;
}

export interface AuthenticatedRequest extends Request {
  user?: JwtPayload;
}

/**
 * Authentication middleware.
 *
 * 1. Extracts the JWT from the Authorization header (Bearer token).
 * 2. Verifies the token signature and expiry.
 * 3. Checks that the device referenced in the token still exists in the
 *    devices table — if another device logged in and wiped the old entry,
 *    this returns 401 ("remote logout" enforcement).
 */
export async function authenticate(
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing or invalid Authorization header',
      };
      res.status(401).json(response);
      return;
    }

    const token = authHeader.substring(7);

    let payload: JwtPayload;
    try {
      payload = jwt.verify(token, config.jwt.secret) as JwtPayload;
    } catch {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid or expired token',
      };
      res.status(401).json(response);
      return;
    }

    // Verify the device still exists (single-session enforcement)
    const device = await Device.findByUserIdAndDeviceId(payload.userId, payload.deviceId);

    if (!device) {
      const response: ApiResponse = {
        success: false,
        error: 'Session invalidated — logged in from another device',
      };
      res.status(401).json(response);
      return;
    }

    // Update last_seen_at
    await Device.updateLastSeen(device.id);

    req.user = payload;
    next();
  } catch (error) {
    console.error('Auth middleware error:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Authentication failed',
    };
    res.status(500).json(response);
  }
}
