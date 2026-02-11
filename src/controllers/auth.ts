import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { User, AuthChallenge, Device } from '../models';
import { generateNonce, verifySignature } from '../utils/crypto';
import { ApiResponse } from '../types';
import { AuthenticatedRequest, JwtPayload } from '../middleware/auth';

/** Max allowed length for deviceId (must fit VARCHAR(255)). */
const MAX_DEVICE_ID_LENGTH = 255;

/** Ed25519 signature is 64 bytes → 88 chars in base64. */
const BASE64_SIGNATURE_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const ED25519_SIGNATURE_BYTES = 64;

/** FCM token constraints. */
const MAX_FCM_TOKEN_LENGTH = 512;
const FCM_TOKEN_REGEX = /^[A-Za-z0-9_\-:.]+$/;

/**
 * POST /api/auth/challenge
 *
 * Generates a cryptographic nonce that the client must sign with its
 * Ed25519 identity key to prove ownership.
 *
 * @body {string} username  - The registered username.
 * @body {string} deviceId  - Client-generated device identifier (max 255 chars).
 *
 * @returns {{ nonce: string }} The hex-encoded nonce to sign.
 *
 * @error 400 - Missing or invalid input fields.
 * @error 401 - Authentication failed (user not found).
 * @error 500 - Internal server error.
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

    if (deviceId.length > MAX_DEVICE_ID_LENGTH) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid deviceId: exceeds maximum length',
      };
      res.status(400).json(response);
      return;
    }

    const sanitizedUsername = username.trim();
    const user = await User.findByUsername(sanitizedUsername);
    if (!user) {
      // Generic error to prevent user enumeration
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
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
 * Verifies the client's Ed25519 signature over the previously issued
 * nonce and, on success, returns a JWT.
 *
 * @body {string}  username   - The registered username.
 * @body {string}  signature  - Base64-encoded Ed25519 signature (64 bytes → 88 chars).
 * @body {string}  deviceId   - Client-generated device identifier (max 255 chars).
 * @body {string}  [fcmToken] - Optional Firebase Cloud Messaging token (max 512 chars).
 *
 * @returns {{ token: string; user: { id: string; username: string } }}
 *
 * @error 400 - Missing / malformed fields, or no active challenge.
 * @error 401 - Authentication failed (bad user, bad signature, etc.).
 * @error 500 - Internal server error.
 */
export async function verifyChallenge(req: Request, res: Response): Promise<void> {
  try {
    const { username, signature, deviceId, fcmToken } = req.body;

    // --- Required field type checks ---
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

    // --- Signature format validation (Ed25519: 64 bytes, base64-encoded) ---
    if (signature.length > 100 || !BASE64_SIGNATURE_REGEX.test(signature)) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid signature format',
      };
      res.status(400).json(response);
      return;
    }
    const decodedSignature = Buffer.from(signature, 'base64');
    if (decodedSignature.length !== ED25519_SIGNATURE_BYTES) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid signature length',
      };
      res.status(400).json(response);
      return;
    }

    // --- deviceId length validation ---
    if (deviceId.length > MAX_DEVICE_ID_LENGTH) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid deviceId: exceeds maximum length',
      };
      res.status(400).json(response);
      return;
    }

    // --- Optional fcmToken validation ---
    if (fcmToken !== undefined && fcmToken !== null) {
      if (typeof fcmToken !== 'string') {
        const response: ApiResponse = {
          success: false,
          error: 'Invalid fcmToken: must be a string',
        };
        res.status(400).json(response);
        return;
      }
      const trimmedFcmToken = fcmToken.trim();
      if (trimmedFcmToken.length === 0 || trimmedFcmToken.length > MAX_FCM_TOKEN_LENGTH) {
        const response: ApiResponse = {
          success: false,
          error: `Invalid fcmToken: length must be between 1 and ${MAX_FCM_TOKEN_LENGTH} characters`,
        };
        res.status(400).json(response);
        return;
      }
      if (!FCM_TOKEN_REGEX.test(trimmedFcmToken)) {
        const response: ApiResponse = {
          success: false,
          error: 'Invalid fcmToken: contains unsupported characters',
        };
        res.status(400).json(response);
        return;
      }
    }

    const sanitizedUsername = username.trim();

    // Find the user (generic error to prevent user enumeration)
    const user = await User.findByUsername(sanitizedUsername);
    if (!user) {
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
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

    // Always consume the challenge to prevent brute-force attempts
    await AuthChallenge.deleteByUserId(user.id);

    if (!isValid) {
      const response: ApiResponse = {
        success: false,
        error: 'Authentication failed',
      };
      res.status(401).json(response);
      return;
    }

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
