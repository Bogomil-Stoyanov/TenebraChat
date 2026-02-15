import { Router, Request, Response } from 'express';
import { SignedPreKey, OneTimePreKey } from '../models';
import { KeyBundleService } from '../services/KeyBundleService';
import { ApiResponse, PreKeyBundle } from '../types';

const router = Router();

// Upload signed pre-key
router.post('/signed-pre-key', async (req: Request, res: Response) => {
  try {
    const { user_id, key_id, public_key, signature } = req.body;

    if (!user_id || key_id === undefined || !public_key || !signature) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: user_id, key_id, public_key, signature',
      };
      return res.status(400).json(response);
    }

    const key = await SignedPreKey.upsert({
      user_id,
      key_id,
      public_key,
      signature,
    });

    const response: ApiResponse<SignedPreKey> = {
      success: true,
      data: key,
      message: 'Signed pre-key uploaded successfully',
    };
    return res.status(201).json(response);
  } catch (error) {
    console.error('Error uploading signed pre-key:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Upload one-time pre-keys (batch)
router.post('/one-time-pre-keys', async (req: Request, res: Response) => {
  try {
    const {
      user_id,
      keys,
    }: { user_id: string; keys: Array<{ key_id: number; public_key: string }> } = req.body;

    if (!user_id || !keys || !Array.isArray(keys) || keys.length === 0) {
      const response: ApiResponse = {
        success: false,
        error: 'Missing required fields: user_id, keys (array)',
      };
      return res.status(400).json(response);
    }

    const keyData = keys.map((k) => ({
      user_id,
      key_id: k.key_id,
      public_key: k.public_key,
    }));

    const createdKeys = await OneTimePreKey.createBatch(keyData);

    const response: ApiResponse<{ count: number; keys: OneTimePreKey[] }> = {
      success: true,
      data: {
        count: createdKeys.length,
        keys: createdKeys,
      },
      message: `${createdKeys.length} one-time pre-keys uploaded successfully`,
    };
    return res.status(201).json(response);
  } catch (error) {
    console.error('Error uploading one-time pre-keys:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get pre-key bundle for establishing a session
router.get('/bundle/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;

    const bundle = await KeyBundleService.getPreKeyBundle(userId);

    if (!bundle) {
      const response: ApiResponse = {
        success: false,
        error: 'User not found or no keys available',
      };
      return res.status(404).json(response);
    }

    const response: ApiResponse<PreKeyBundle> = {
      success: true,
      data: bundle,
    };
    return res.json(response);
  } catch (error) {
    console.error('Error fetching pre-key bundle:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get one-time pre-key count for a user
router.get('/one-time-pre-keys/count/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const count = await KeyBundleService.getOneTimePreKeyCount(userId);

    const response: ApiResponse<{ count: number; needsMore: boolean }> = {
      success: true,
      data: {
        count,
        needsMore: count < 10,
      },
    };
    return res.json(response);
  } catch (error) {
    console.error('Error fetching pre-key count:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

// Get user's signed pre-keys (for debugging/admin)
router.get('/signed-pre-keys/:userId', async (req: Request, res: Response) => {
  try {
    const { userId } = req.params;
    const keys = await SignedPreKey.query()
      .where({ user_id: userId })
      .orderBy('created_at', 'desc');

    const response: ApiResponse<SignedPreKey[]> = {
      success: true,
      data: keys,
    };
    return res.json(response);
  } catch (error) {
    console.error('Error fetching signed pre-keys:', error);
    const response: ApiResponse = {
      success: false,
      error: 'Internal server error',
    };
    return res.status(500).json(response);
  }
});

export default router;
