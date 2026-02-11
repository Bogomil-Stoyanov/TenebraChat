import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { User, AuthChallenge, Device } from '../models';
import { generateNonce, verifySignature } from '../utils/crypto';
import { ApiResponse } from '../types';
import { AuthenticatedRequest, JwtPayload } from '../middleware/auth';

/**
 * POST /api/auth/challenge
 *
 * Input: { username, deviceId }
 * Output: { nonce }
 */
export async function generateChallenge(req: Request, res: Response): Promise<void> {
  try {
    const { username, deviceId } = req.body;

    if (
      typeof username !== 'string' ||
      typeof deviceId !== 'string' ||
      username.trim().length === 0 ||
      deviceId.trim().length === 0
    ) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: username, deviceId',
      };
      res.status(400).json(response);
      return;
    }

    const sanitizedUsername = username.trim();
    const user = await User.findByUsername(sanitizedUsername);
    if (!user) {
      const response: ApiResponse = {
        success: false,
        error: 'User not found',
      };
      res.status(404).json(response);
      return;
    }

    const nonce = generateNonce();
    await AuthChallenge.createForUser(user.id, nonce);

    const response: ApiResponse<{ nonce: string }> = {
      success: true,
      data: { nonce },
    };
    res.json(response);
  } catch (error) {
    console.error('Error generating challenge:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    res.status(500).json(response);
  }
}

/**
 * POST /api/auth/verify
 *
 * Input: { username, signature, deviceId, fcmToken? }
 * Output: { token, user }
 */
export async function verifyChallenge(req: Request, res: Response): Promise<void> {
  try {
    const { username, signature, deviceId, fcmToken } = req.body;

    if (
      typeof username !== 'string' ||
      typeof signature !== 'string' ||
      typeof deviceId !== 'string' ||
      username.trim().length === 0 ||
      signature.trim().length === 0 ||
      deviceId.trim().length === 0
    ) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: username, signature, deviceId',
      };
      res.status(400).json(response);
      return;
    }

    if (fcmToken !== undefined && typeof fcmToken !== 'string') {
      const response: ApiResponse = {
        success: false,
        error: 'fcmToken must be a string',
      };
      res.status(400).json(response);
      return;
    }

    const sanitizedUsername = username.trim();

    // Find the user
    const user = await User.findByUsername(sanitizedUsername);
    if (!user) {
      const response: ApiResponse = {
        success: false,
        error: 'User not found',
      };
      res.status(404).json(response);
      return;
    }

    // Find the active challenge
    const challenge = await AuthChallenge.findActiveByUserId(user.id);
    if (!challenge) {
      const response: ApiResponse = {
        success: false,
        error: 'No active challenge found — request a new one',
      };
      res.status(400).json(response);
      return;
    }

    // Verify signature against identity_public_key and nonce
    const isValid = verifySignature(user.identity_public_key, challenge.nonce, signature);

    if (!isValid) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid signature',
      };
      res.status(401).json(response);
      return;
    }

    // Signature valid — consume the challenge
    await AuthChallenge.deleteByUserId(user.id);

    // Single session enforcement:
    // Delete all devices for this user and insert the current one
    await Device.upsertDevice(
      user.id,
      deviceId,
      user.identity_public_key,
      user.registration_id,
      fcmToken
    );

    // Generate JWT
    const payload: JwtPayload = {
      userId: user.id,
      deviceId,
    };

    const token = jwt.sign(payload, config.jwt.secret, {
      expiresIn: config.jwt.expiresIn,
    } as jwt.SignOptions);

    const response: ApiResponse<{ token: string; user: { id: string; username: string } }> = {
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
        },
      },
    };
    res.json(response);
  } catch (error) {
    console.error('Error verifying challenge:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    res.status(500).json(response);
  }
}

/**
 * POST /api/auth/logout
 *
 * Deletes the device entry for the current session, effectively
 * invalidating the JWT (the auth middleware will reject it).
 */
export async function logout(req: AuthenticatedRequest, res: Response): Promise<void> {
  try {
    if (!req.user) {
      const response: ApiResponse = {
        success: false,
        error: 'Not authenticated',
      };
      res.status(401).json(response);
      return;
    }

    await Device.deleteByUserIdAndDeviceId(req.user.userId, req.user.deviceId);

    const response: ApiResponse = {
      success: true,
      message: 'Logged out successfully',
    };
    res.json(response);
  } catch (error) {
    console.error('Error during logout:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    res.status(500).json(response);
  }
}
