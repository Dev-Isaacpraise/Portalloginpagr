/**
 * Authentication Routes
 * ---------------------
 * Handles candidate registration, primary password verification (Step 1), and logout.
 */

import { Router } from 'express';
import { AuthController } from '../controllers/auth.controller';
import { loginRateLimiter } from '../middleware/rateLimiter';
import { redirectIfAuthenticated } from '../middleware/auth.middleware';

const router = Router();

// Primary login routes (rate limited against dictionary & brute-force attacks)
router.get('/login', redirectIfAuthenticated, AuthController.showLogin);
router.post('/login', loginRateLimiter, AuthController.login);

// Registration routes
router.get('/register', redirectIfAuthenticated, AuthController.showRegister);
router.post('/register', AuthController.register);

// Logout
router.get('/logout', AuthController.logout);

export default router;
