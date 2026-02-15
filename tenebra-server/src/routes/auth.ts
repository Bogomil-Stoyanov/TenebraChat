import { Router } from 'express';
import rateLimit from 'express-rate-limit';
import { generateChallenge, verifyChallenge, logout } from '../controllers/auth';
import { authenticate } from '../middleware/auth';

const router = Router();

// Rate limiter for challenge requests: 10 per minute per IP
const challengeLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many challenge requests, please try again later.' },
});

// Stricter rate limiter for verify: 5 per minute per IP
const verifyLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 5,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many verification attempts, please try again later.' },
});

// Rate limiter for logout: 10 per minute per IP
const logoutLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 10,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, error: 'Too many logout requests, please try again later.' },
});

// POST /api/auth/challenge - Request a login challenge (nonce)
router.post('/challenge', challengeLimiter, generateChallenge);

// POST /api/auth/verify - Verify signed challenge and get JWT
router.post('/verify', verifyLimiter, verifyChallenge);

// POST /api/auth/logout - Invalidate current session
router.post('/logout', logoutLimiter, authenticate, logout);

export default router;
