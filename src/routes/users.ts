import { Router, Request, Response } from 'express';
import { User } from '../models';
import { ApiResponse } from '../types';

const router = Router();

// Register a new user
router.post('/register', async (req: Request, res: Response) => {
  try {
    const { username, identity_public_key, registration_id } = req.body;

    if (!username || !identity_public_key || registration_id === undefined) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: username, identity_public_key, registration_id',
      };
      return res.status(400).json(response);
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

    const user = await User.query().insertAndFetch({
      username,
      identity_public_key,
      registration_id,
    });

    const response: ApiResponse<User> = {
      success: true,
      data: user,
      message: 'User registered successfully',
    };
    return res.status(201).json(response);
  } catch (error) {
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

// Update user identity key (for key rotation)
router.put('/:id/identity', async (req: Request, res: Response) => {
  try {
    const { id } = req.params;
    const { identity_public_key, registration_id } = req.body;

    if (!identity_public_key || registration_id === undefined) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: identity_public_key, registration_id',
      };
      return res.status(400).json(response);
    }

    const user = await User.query().patchAndFetchById(id, {
      identity_public_key,
      registration_id,
    });

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
      message: 'Identity key updated successfully',
    };
    return res.json(response);
  } catch (error) {
    console.error('Error updating user:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

export default router;
