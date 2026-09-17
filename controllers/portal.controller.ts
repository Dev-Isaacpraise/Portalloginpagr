/**
 * Portal Controller (Protected Dashboard & Credential Verification)
 * -----------------------------------------------------------------
 * Serves the authenticated candidate portal for academic recruitment.
 * Visualizes:
 * 1. Candidate identity & verified matric/application registration number
 * 2. Academic credentials (Degree, Institution, Grade, Completion, SHA256 Verification Hash)
 * 3. Recent Login & MFA Security Audit Log (showing timestamp, IP, Step 1/Step 2, and success/fail)
 *    directly supporting the security monitoring objective of the thesis.
 */

import { Request, Response } from 'express';
import { AcademicRecordModel } from '../models/academicRecord.model';
import { LoginAttemptModel } from '../models/loginAttempt.model';
import { UserModel } from '../models/user.model';

export class PortalController {
  /**
   * GET /dashboard
   * Session-gated dashboard view
   */
  static async showDashboard(req: Request, res: Response) {
    const sessionUser = (req.session as any)?.user || (req as any)?.user;

    if (!sessionUser) {
      return res.redirect('/login');
    }

    try {
      // 1. Fetch user's academic records
      const academicRecords = await AcademicRecordModel.getByUserId(sessionUser.id);

      // 2. Fetch user's recent login audit attempts
      const loginAttempts = await LoginAttemptModel.getRecentByUser(sessionUser.username, 8);

      // 3. Check for freshly activated query param
      const mfaActivated = req.query.mfaActivated === 'true';

      res.render('dashboard', {
        user: sessionUser,
        records: academicRecords,
        loginAttempts: loginAttempts,
        mfaActivated
      });
    } catch (err: any) {
      console.error('Dashboard loading error:', err);
      res.status(500).send('Error loading portal dashboard');
    }
  }

  /**
   * POST /dashboard/reset-mfa (Demonstration Helper for Thesis Defense)
   * Allows the thesis presenter to reset MFA so they can demonstrate enrollment again.
   */
  static async resetMfaForDemo(req: Request, res: Response) {
    const sessionUser = (req.session as any).user;
    if (!sessionUser) {
      return res.redirect('/login');
    }

    await UserModel.disableMfa(sessionUser.id);
    // Transition user back to mfaSetupPending
    (req.session as any).mfaSetupPending = {
      id: sessionUser.id,
      username: sessionUser.username,
      email: sessionUser.email,
      fullName: sessionUser.fullName,
      staffId: sessionUser.staffId,
      department: sessionUser.department,
      role: sessionUser.role
    };
    delete (req.session as any).user;

    res.redirect('/mfa/setup?reset=true');
  }
}
