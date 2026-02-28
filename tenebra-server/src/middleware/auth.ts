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
 * Extract a Bearer token from the Authorization header, verify it as a
 * valid JWT, and validate that the payload has the expected shape.
 *
 * Returns a validated `JwtPayload` on success, or `null` if any step fails
 * (missing/malformed header, invalid/expired JWT, unexpected payload shape).
 *
 * Combining extraction + verification into one function ensures there is no
 * user-controlled branch that guards the cryptographic verification step,
 * which satisfies CodeQL's `js/user-controlled-bypass` rule.
 */
function verifyAuthHeader(header: unknown): JwtPayload | null {
  if (typeof header !== 'string' || !header.startsWith('Bearer ')) {
    return null;
  }

  const token = header.substring(7);
  if (token.length === 0) {
    return null;
  }

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
    const payload = verifyAuthHeader(req.headers.authorization);

    if (payload === null) {
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
