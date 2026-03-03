import { Router, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import { User, InviteCode } from '../models';
import { ApiResponse } from '../types';
import knex from '../database/connection';

const router = Router();

// Rate limiter for registration: 5 per 15 minutes per IP
const registerLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many registration attempts, please try again later.' },
});

// Register a new user
router.post('/register', registerLimiter, async (req: Request, res: Response) => {
  try {
    const { username, identity_public_key, registration_id, inviteCode } = req.body;

    if (!username || !identity_public_key || registration_id === undefined) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: username, identity_public_key, registration_id',
      };
      return res.status(400).json(response);
    }

    // Validate invite code
    if (!inviteCode || typeof inviteCode !== 'string' || inviteCode.trim().length === 0) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid or expired invite code',
      };
      return res.status(403).json(response);
    }

    const validInvite = await InviteCode.findValidCode(inviteCode.trim());
    if (!validInvite) {
      const response: ApiResponse = {
        success: false,
        error: 'Invalid or expired invite code',
      };
      return res.status(403).json(response);
    }

    // Check if username already exists
    const existingUser = await User.findByUsername(username);
    if (existingUser) {
      const response: ApiResponse = {
        success: false,
        error: 'Username already exists',
      };
      return res.status(409).json(response);
    }

    // Create user and consume invite code atomically in a transaction
    const user = await knex.transaction(async (trx) => {
      // Re-validate and lock the invite row to prevent concurrent consumption
      const lockedInvite = await InviteCode.query(trx)
        .findOne({ code: inviteCode.trim(), is_used: false })
        .forUpdate();

      if (!lockedInvite) {
        throw Object.assign(new Error('Invalid or expired invite code'), { statusCode: 403 });
      }

      const newUser = await User.query(trx).insertAndFetch({
        username,
        identity_public_key,
        registration_id,
      });

      const updatedRows = await InviteCode.query(trx)
        .patch({ is_used: true, used_by: newUser.id })
        .where({ id: lockedInvite.id, is_used: false });

      if (updatedRows !== 1) {
        throw Object.assign(new Error('Invalid or expired invite code'), { statusCode: 403 });
      }

      return newUser;
    });

    const response: ApiResponse<User> = {
      success: true,
      data: user,
      message: 'User registered successfully',
    };
    return res.status(201).json(response);
  } catch (error: unknown) {
    const err = error as { statusCode?: number; message?: string };
    if (err.statusCode === 403) {
      const response: ApiResponse = { success: false, error: err.message ?? 'Forbidden' };
      return res.status(403).json(response);
    }
    console.error('Error registering user:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get user by username
router.get('/by-username/:username', async (req: Request, res: Response) => {
  try {
    const { username } = req.params;
    const user = await User.findByUsername(username);

    if (!user) {
      const response: ApiResponse = {
        success: false,
        error: 'User not found',
      };
      return res.status(404).json(response);
    }

    const response: ApiResponse<User> = {
      success: true,
      data: user,
    };
    return res.json(response);
  } catch (error) {
    console.error('Error fetching user:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get user by ID
router.get('/:id', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const user = await User.query().findById(id);

    if (!user) {
      const response: ApiResponse = {
        success: false,
        error: 'User not found',
      };
      return res.status(404).json(response);
    }

    const response: ApiResponse<User> = {
      success: true,
      data: user,
    };
    return res.json(response);
  } catch (error) {
    console.error('Error fetching user:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

export default router;
