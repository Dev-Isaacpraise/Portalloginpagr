/**
 * MFA Routes (RFC 6238 TOTP Protocol)
 * ------------------------------------
 * Endpoints for:
 * 1. Generating shared secret & QR code (/mfa/setup)
 * 2. Confirming activation with first 6-digit code (/mfa/confirm)
 * 3. Step 2 login verification (/mfa/verify)
 * Protected with rate limiting to prevent 6-digit token enumeration.
 */

import { Router } from 'express';
import { MfaController } from '../controllers/mfa.controller';
import { mfaRateLimiter } from '../middleware/rateLimiter';
import { requireMfaPending } from '../middleware/auth.middleware';

const router = Router();

// MFA Setup and Activation
router.get('/mfa/setup', MfaController.showSetup);
router.post('/mfa/setup', MfaController.setupPost);
router.post('/mfa/confirm', mfaRateLimiter, MfaController.confirm);

// MFA Step 2 Verification during Login
router.get('/mfa/verify', requireMfaPending, MfaController.showVerify);
router.post('/mfa/verify', requireMfaPending, mfaRateLimiter, MfaController.verify);

// Live TOTP Epoch Sync API (Thesis defense presentation helper)
router.get('/api/mfa/epoch-time', MfaController.getEpochInfo);

export default router;
