/**
 * Portal Routes
 * -------------
 * Serves the authenticated Academic Recruitment Credential Verification Portal.
 * Guarded by session-based authentication middleware.
 */

import { Router } from 'express';
import { PortalController } from '../controllers/portal.controller';
import { requireAuth } from '../middleware/auth.middleware';

const router = Router();

// Root route redirects to dashboard if authenticated or login if unauthenticated
router.get('/', (req, res) => {
  if (req.session && (req.session as any).user) {
    return res.redirect('/dashboard');
  }
  res.redirect('/login');
});

// Protected candidate dashboard
router.get('/dashboard', requireAuth, PortalController.showDashboard);

// Thesis defense demo helper: Reset MFA on current account to demonstrate QR scanning again
router.post('/dashboard/reset-mfa', requireAuth, PortalController.resetMfaForDemo);

export default router;
