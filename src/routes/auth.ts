import { Router } from 'express';
import { generateChallenge, verifyChallenge, logout } from '../controllers/auth';
import { authenticate } from '../middleware/auth';

const router = Router();

// POST /api/auth/challenge - Request a login challenge (nonce)
router.post('/challenge', generateChallenge);

// POST /api/auth/verify - Verify signed challenge and get JWT
router.post('/verify', verifyChallenge);

// POST /api/auth/logout - Invalidate current session
router.post('/logout', authenticate, logout);

export default router;
