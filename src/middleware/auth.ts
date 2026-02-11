import { Request, Response, NextFunction } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { Device } from '../models';
import { ApiResponse } from '../types';

/**
 * Extract the Bearer token from an Authorization header value.
 * Returns `null` if the header is missing, malformed, or the token is empty.
 *
 * Extracting this into a standalone function avoids CodeQL's
 * "user-controlled bypass of security check" pattern.
 */
function extractBearerToken(header: unknown): string | null {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    return null;
  }
  const token = header.substring(7);
  return token.length > 0 ? token : null;
}

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
    const token = extractBearerToken(req.headers.authorization);

    if (token === null) {
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
      return;
    }

    let payload: JwtPayload;
    try {
      const decoded = jwt.verify(token, config.jwt.secret);

      // Runtime validation of JWT payload structure
      if (
        typeof decoded !== 'object' ||
        decoded === null ||
        typeof (decoded as JwtPayload).userId !== 'string' ||
        typeof (decoded as JwtPayload).deviceId !== 'string'
      ) {
        const response: ApiResponse = {
          success: false,
          error: 'Authentication failed',
        };
        res.status(401).json(response);
        return;
      }

      payload = decoded as JwtPayload;
    } catch {
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
      return;
    }

    // Verify the device still exists (single-session enforcement)
    const device = await Device.findByUserIdAndDeviceId(payload.userId, payload.deviceId);

    if (!device) {
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
      return;
    }

    // Update last_seen_at (fire-and-forget — should not block authenticated requests)
    Device.updateLastSeen(device.id).catch((updateError) => {
      console.error('Failed to update device last_seen_at:', updateError);
    });

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
