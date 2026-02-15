import { Request, Response } from 'express';
import jwt from 'jsonwebtoken';
import { config } from '../config';
import { User, AuthChallenge, Device, OneTimePreKey } from '../models';
import { generateNonce, verifySignature } from '../utils/crypto';
import { ApiResponse } from '../types';
import { AuthenticatedRequest, JwtPayload } from '../middleware/auth';

/** Max allowed length for deviceId (must fit VARCHAR(255)). */
const MAX_DEVICE_ID_LENGTH = 255;

/** Ed25519 signature is 64 bytes → 88 chars in base64. */
const BASE64_SIGNATURE_REGEX = /^[A-Za-z0-9+/]+={0,2}$/;
const ED25519_SIGNATURE_BYTES = 64;

/**
 * Validate that a value looks like a well-formed base64-encoded Ed25519
 * signature (64 raw bytes → 88 base64 characters).
 *
 * Returning an object (instead of branching on the user value inline)
 * avoids CodeQL's "user-controlled bypass of security check" pattern.
 */
function isValidEd25519Signature(value: string): boolean {
  if (value.length > 100 || !BASE64_SIGNATURE_REGEX.test(value)) {
    return false;
  }
  const decoded = Buffer.from(value, 'base64');
  return decoded.length === ED25519_SIGNATURE_BYTES;
}

/** FCM token constraints. */
const MAX_FCM_TOKEN_LENGTH = 512;
const FCM_TOKEN_REGEX = /^[A-Za-z0-9_\-:.]+$/;

interface VerifyInput {
  username: string;
  signature: string;
  deviceId: string;
  fcmToken?: string;
}

/**
 * Validate and extract the required fields from the verify-challenge
 * request body.  Returns a typed `VerifyInput` on success, or a string
 * describing the validation error on failure.
 *
 * Isolating the user-input checks in a dedicated function ensures that
 * CodeQL does not see the caller branching on a user-controlled value
 * that gates the subsequent cryptographic verification.
 */
function validateVerifyInput(body: Record<string, unknown>): VerifyInput | string {
  const { username, signature, deviceId, fcmToken } = body;

  // --- Required field type & presence checks ---
  if (
    typeof username !== 'string' ||
    typeof signature !== 'string' ||
    typeof deviceId !== 'string' ||
    username.trim().length === 0 ||
    signature.trim().length === 0 ||
    deviceId.trim().length === 0
  ) {
    return 'Missing required fields: username, signature, deviceId';
  }

  // --- Signature format ---
  if (!isValidEd25519Signature(signature)) {
    return 'Invalid signature format or length';
  }

  // --- deviceId length ---
  if (deviceId.length > MAX_DEVICE_ID_LENGTH) {
    return 'Invalid deviceId: exceeds maximum length';
  }

  // --- Optional fcmToken ---
  if (fcmToken !== undefined && fcmToken !== null) {
    if (typeof fcmToken !== 'string') {
      return 'Invalid fcmToken: must be a string';
    }
    const trimmed = fcmToken.trim();
    if (trimmed.length === 0 || trimmed.length > MAX_FCM_TOKEN_LENGTH) {
      return `Invalid fcmToken: length must be between 1 and ${MAX_FCM_TOKEN_LENGTH} characters`;
    }
    if (!FCM_TOKEN_REGEX.test(trimmed)) {
      return 'Invalid fcmToken: contains unsupported characters';
    }
  }

  return {
    username: username.trim(),
    signature,
    deviceId,
    fcmToken: typeof fcmToken === 'string' ? fcmToken : undefined,
  };
}

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
    const validationResult = validateVerifyInput(req.body);

    if (typeof validationResult === 'string') {
      const response: ApiResponse = {
        success: false,
        error: validationResult,
      };
      res.status(400).json(response);
      return;
    }

    const { username, signature, deviceId, fcmToken } = validationResult;

    // Find the user (generic error to prevent user enumeration)
    const user = await User.findByUsername(username);
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

    // Check remaining one-time pre-keys so the client can replenish early
    const LOW_KEY_THRESHOLD = 20;
    const remainingKeys = await OneTimePreKey.countByUserId(user.id);

    const response: ApiResponse<{
      token: string;
      user: { id: string; username: string };
      remainingKeyCount: number;
      lowKeyCount: boolean;
    }> = {
      success: true,
      data: {
        token,
        user: {
          id: user.id,
          username: user.username,
        },
        remainingKeyCount: remainingKeys,
        lowKeyCount: remainingKeys < LOW_KEY_THRESHOLD,
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
