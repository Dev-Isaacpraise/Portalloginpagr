/**
 * MFA Controller (Step 2: Time-based One-Time Password / TOTP)
 * -----------------------------------------------------------
 * Implements RFC 6238 Time-based One-Time Password algorithm:
 * 1. POST /mfa/setup  - Generates Base32 shared secret, binds temporarily to user, returns QR code
 * 2. POST /mfa/confirm - Verifies initial OTP code to confirm setup and activate MFA on account
 * 3. POST /mfa/verify  - Second factor during login; validates 6-digit code before granting session
 * 
 * Cryptographic & Engineering Notes for Thesis Defense:
 * - Shared Secret: 160-bit (20-byte) or 256-bit cryptographically secure pseudorandom number,
 *   encoded in Base32 per RFC 3548.
 * - Time Step (T0): Standard 30 seconds. Counter C = floor((UnixTime - T0) / 30).
 * - HMAC: HMAC-SHA1(Secret, C).
 * - Truncation: Dynamic Truncation extracts 4-byte string, converted to 6-digit decimal (000000 - 999999).
 * - Clock Skew: A window of +/- 1 time step is tolerated to accommodate mobile clock drift.
 */

import { Request, Response } from 'express';
import { generateSecret, generateURI, verifySync, generateSync } from 'otplib';
import QRCode from 'qrcode';
import { UserModel } from '../models/user.model';
import { LoginAttemptModel } from '../models/loginAttempt.model';
import { TicketService } from '../services/ticket.service';

export class MfaController {
  /**
   * GET /mfa/setup
   * Displays the MFA enrollment view with QR code, secret key, and confirmation form
   */
  static async showSetup(req: Request, res: Response) {
    const ticket = (req.query.ticket || req.body.ticket) as string;
    const pendingUser = (req.session as any).mfaSetupPending || (ticket ? TicketService.getPendingTicket(ticket) : null) || (req.session as any).user;

    if (!pendingUser) {
      return res.redirect('/login?error=Please+log+in+to+configure+two-factor+authentication.');
    }

    try {
      // 1. Generate a new cryptographically secure Base32 secret key (RFC 3548)
      const secret = generateSecret();

      // 2. Persist temporary unconfirmed secret in database
      await UserModel.setTempMfaSecret(pendingUser.id, secret);

      // 3. Format standard otpauth:// URI for authenticator apps
      const issuer = 'Federal University Lokoja (Student Portal)';
      const accountName = pendingUser.matricNo || pendingUser.username;
      const otpauthUri = generateURI({
        issuer,
        label: accountName,
        secret
      });

      // 4. Render QR code image as base64 Data URL
      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri, {
        errorCorrectionLevel: 'M',
        margin: 2,
        width: 220,
        color: {
          dark: '#0B2545',
          light: '#FFFFFF'
        }
      });

      // Format secret into clean readable 4-character blocks: XXXX XXXX XXXX...
      const formattedSecret = secret.match(/.{1,4}/g)?.join(' ') || secret;

      return res.render('mfa-setup', {
        user: pendingUser,
        qrCodeUrl: qrCodeDataUrl,
        rawSecret: secret,
        formattedSecret,
        ticket: ticket || '',
        error: null,
        registered: req.query.registered === 'true'
      });
    } catch (err) {
      console.error('MFA Setup Generation Error:', err);
      return res.status(500).render('login', {
        error: 'Unable to initialize MFA QR code. Please try again.',
        matricNo: pendingUser.matricNo || pendingUser.username,
        username: pendingUser.username,
        rateLimited: false
      });
    }
  }

  /**
   * POST /mfa/setup
   * API endpoint to programmatically generate or regenerate TOTP secret
   */
  static async setupPost(req: Request, res: Response) {
    const pendingUser = (req.session as any).mfaSetupPending || (req.session as any).user;
    if (!pendingUser) {
      return res.status(401).json({ success: false, error: 'Authentication required' });
    }

    try {
      const secret = generateSecret();
      await UserModel.setTempMfaSecret(pendingUser.id, secret);

      const issuer = 'Federal University Lokoja (Recruitment)';
      const otpauthUri = generateURI({
        issuer,
        label: pendingUser.username,
        secret
      });
      const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri, { margin: 2, width: 220 });

      return res.json({
        success: true,
        secret,
        otpauthUri,
        qrCodeDataUrl
      });
    } catch (err: any) {
      return res.status(500).json({ success: false, error: err.message });
    }
  }

  /**
   * POST /mfa/confirm
   * Verifies the applicant's first TOTP code.
   * If valid, activates MFA in database and establishes full authenticated session.
   */
  static async confirm(req: Request, res: Response) {
    const ticket = (req.body.ticket || req.query.ticket) as string;
    const pendingUser = (req.session as any).mfaSetupPending || (ticket ? TicketService.getPendingTicket(ticket) : null) || (req.session as any).user;
    const clientIp = req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!pendingUser) {
      return res.redirect('/login?error=Session+expired.+Please+sign+in+again.');
    }

    // Extract 6-digit code (sanitize whitespace/dashes)
    let { code, secret } = req.body;
    code = (code || '').toString().replace(/[\s-]/g, '');

    if (!code || code.length !== 6) {
      return res.status(400).render('mfa-setup', {
        user: pendingUser,
        qrCodeUrl: req.body.qrCodeUrl || '',
        rawSecret: secret,
        formattedSecret: secret ? secret.match(/.{1,4}/g)?.join(' ') : '',
        ticket: ticket || '',
        error: 'Please enter a complete 6-digit verification code.',
        registered: false
      });
    }

    try {
      // Re-fetch user to retrieve unconfirmed temporary secret
      const user = await UserModel.findById(pendingUser.id);
      const secretToVerify = secret || user?.mfa_temp_secret;

      if (!secretToVerify) {
        return res.redirect('/mfa/setup?error=Secret+key+missing.+Please+restart+setup.');
      }

      // Step 2 Verification via RFC 6238 TOTP algorithm with 30s tolerance (window: 1)
      const verificationResult = verifySync({
        token: code,
        secret: secretToVerify,
        epochTolerance: 30
      });
      const isValid = Boolean(verificationResult && verificationResult.valid);

      if (!isValid) {
        // Log failed verification attempt
        await LoginAttemptModel.log({
          username: pendingUser.username,
          ip_address: clientIp,
          attempt_type: 'TOTP_STEP_2',
          status: 'FAILED',
          failure_reason: 'Invalid 6-digit activation code (out of time window or incorrect input)',
          user_agent: userAgent
        });

        const issuer = 'Federal University Lokoja (Student Portal)';
        const otpauthUri = generateURI({
          issuer,
          label: pendingUser.matricNo || pendingUser.username,
          secret: secretToVerify
        });
        const qrCodeDataUrl = await QRCode.toDataURL(otpauthUri, { margin: 2, width: 220 });

        return res.status(400).render('mfa-setup', {
          user: pendingUser,
          qrCodeUrl: qrCodeDataUrl,
          rawSecret: secretToVerify,
          formattedSecret: secretToVerify.match(/.{1,4}/g)?.join(' ') || secretToVerify,
          ticket: ticket || '',
          error: 'Invalid 6-digit code. Please verify the code in your authenticator app before it expires (30s window).',
          registered: false
        });
      }

      // CODE IS VALID: Promote temporary secret to active MFA secret
      await UserModel.activateMfa(pendingUser.id, secretToVerify);

      // Log successful activation & authentication
      await LoginAttemptModel.log({
        username: pendingUser.username,
        ip_address: clientIp,
        attempt_type: 'TOTP_STEP_2',
        status: 'SUCCESS',
        failure_reason: undefined,
        user_agent: userAgent
      });

      // Issue full user session
      const fullUser = await UserModel.findById(pendingUser.id);
      delete (req.session as any).mfaSetupPending;
      delete (req.session as any).mfaPendingUser;

      const userSession = {
        id: fullUser!.id,
        matricNo: fullUser!.matric_no || fullUser!.username,
        username: fullUser!.matric_no || fullUser!.username,
        email: fullUser!.email,
        fullName: fullUser!.full_name,
        staffId: fullUser!.staff_id || fullUser!.matric_no,
        department: fullUser!.department,
        faculty: fullUser!.faculty || 'Faculty of Science',
        level: fullUser!.level || '400 Level',
        rrrCode: fullUser!.rrr_code,
        role: fullUser!.role,
        mfaActive: true
      };

      (req.session as any).user = userSession;

      const authTicket = TicketService.createAuthTicket(userSession);
      if (ticket) TicketService.consumePendingTicket(ticket);

      return req.session.save((saveErr) => {
        if (saveErr) console.error('Session save error:', saveErr);
        res.redirect(`/dashboard?mfaActivated=true&auth_token=${authTicket}`);
      });
    } catch (err: any) {
      console.error('MFA Confirm Error:', err);
      return res.status(500).redirect('/mfa/setup?error=Server+error+verifying+MFA+code');
    }
  }

  /**
   * GET /mfa/verify
   * Renders Step 2 Login Verification screen (6-digit spaced input boxes + refresh countdown)
   */
  static showVerify(req: Request, res: Response) {
    const ticket = (req.query.ticket || req.body.ticket) as string;
    const pendingUser = (req.session as any).mfaPendingUser || (ticket ? TicketService.getPendingTicket(ticket) : null);

    if (!pendingUser) {
      return res.redirect('/login?notice=Please+sign+in+first');
    }

    res.render('mfa-verify', {
      matricNo: pendingUser.matricNo || pendingUser.username,
      username: pendingUser.matricNo || pendingUser.username,
      fullName: pendingUser.fullName,
      secretSnippet: pendingUser.secretSnippet,
      ticket: ticket || '',
      error: null,
      rateLimited: false
    });
  }

  /**
   * POST /mfa/verify
   * Validates TOTP code entered during Step 2 of login.
   * Only upon success is the session established!
   */
  static async verify(req: Request, res: Response) {
    const ticket = (req.body.ticket || req.query.ticket) as string;
    const pendingUser = (req.session as any).mfaPendingUser || (ticket ? TicketService.getPendingTicket(ticket) : null);
    const clientIp = req.ip || (req.headers['x-forwarded-for'] as string) || '127.0.0.1';
    const userAgent = req.headers['user-agent'] || 'Unknown';

    if (!pendingUser) {
      return res.redirect('/login?error=Session+expired.+Please+start+from+login.');
    }

    // Extract 6-digit code
    let { code } = req.body;
    code = (code || '').toString().replace(/[\s-]/g, '');

    if (!code || code.length !== 6) {
      await LoginAttemptModel.log({
        username: pendingUser.username,
        ip_address: clientIp,
        attempt_type: 'TOTP_STEP_2',
        status: 'FAILED',
        failure_reason: 'Incomplete code submission (<6 digits)',
        user_agent: userAgent
      });

      return res.status(400).render('mfa-verify', {
        matricNo: pendingUser.matricNo || pendingUser.username,
        username: pendingUser.username,
        fullName: pendingUser.fullName,
        secretSnippet: pendingUser.secretSnippet,
        ticket: ticket || '',
        error: 'Please enter a complete 6-digit verification code.',
        rateLimited: false
      });
    }

    try {
      // Retrieve user and their cryptographically stored active secret
      const user = await UserModel.findById(pendingUser.id);
      if (!user || !user.mfa_secret) {
        return res.redirect('/login?error=MFA+configuration+corrupted.+Please+contact+administrator.');
      }

      // Verify token with RFC 6238 TOTP algorithm (30s window tolerance)
      const verificationResult = verifySync({
        token: code,
        secret: user.mfa_secret,
        epochTolerance: 30
      });
      const isValid = Boolean(verificationResult && verificationResult.valid);

      if (!isValid) {
        // Log security failure for audit log
        await LoginAttemptModel.log({
          username: pendingUser.username,
          ip_address: clientIp,
          attempt_type: 'TOTP_STEP_2',
          status: 'FAILED',
          failure_reason: 'Invalid 6-digit TOTP token mismatch',
          user_agent: userAgent
        });

        return res.status(401).render('mfa-verify', {
          matricNo: pendingUser.matricNo || pendingUser.username,
          username: pendingUser.username,
          fullName: pendingUser.fullName,
          secretSnippet: pendingUser.secretSnippet,
          ticket: ticket || '',
          error: 'Verification code incorrect or expired. Codes refresh every 30 seconds.',
          rateLimited: false
        });
      }

      // Verification SUCCESS: Log the successful Step 2 completion
      await LoginAttemptModel.log({
        username: pendingUser.username,
        ip_address: clientIp,
        attempt_type: 'TOTP_STEP_2',
        status: 'SUCCESS',
        failure_reason: undefined,
        user_agent: userAgent
      });

      // Clear pending state and issue authenticated session
      delete (req.session as any).mfaPendingUser;

      const userSession = {
        id: user.id,
        matricNo: user.matric_no || user.username,
        username: user.matric_no || user.username,
        email: user.email,
        fullName: user.full_name,
        staffId: user.staff_id || user.matric_no,
        department: user.department,
        faculty: user.faculty || 'Faculty of Science',
        level: user.level || '400 Level',
        rrrCode: user.rrr_code,
        role: user.role,
        mfaActive: true,
        loginTime: new Date().toISOString()
      };

      (req.session as any).user = userSession;

      const authTicket = TicketService.createAuthTicket(userSession);
      if (ticket) TicketService.consumePendingTicket(ticket);

      return req.session.save((saveErr) => {
        if (saveErr) console.error('Session save error:', saveErr);
        res.redirect(`/dashboard?auth_token=${authTicket}`);
      });
    } catch (err: any) {
      console.error('MFA verification error:', err);
      return res.status(500).render('mfa-verify', {
        matricNo: pendingUser.matricNo || pendingUser.username,
        username: pendingUser.username,
        fullName: pendingUser.fullName,
        secretSnippet: pendingUser.secretSnippet,
        ticket: ticket || '',
        error: 'System error during two-factor validation. Please retry.',
        rateLimited: false
      });
    }
  }

  /**
   * Helper endpoint: GET /api/mfa/epoch-time
   * Returns remaining seconds in the current 30-second epoch window,
   * plus generates the simulated token for the current pending/active user for testing/defense.
   */
  static async getEpochInfo(req: Request, res: Response) {
    const epochSeconds = Math.floor(Date.now() / 1000);
    const step = 30;
    const timeRemaining = step - (epochSeconds % step);

    const ticket = (req.query.ticket || req.headers['x-mfa-ticket']) as string;
    const pendingUser = (req.session as any).mfaPendingUser || 
      (ticket ? TicketService.getPendingTicket(ticket) : null) || 
      (req.session as any).mfaSetupPending || 
      (req.session as any).user;

    let simulatedCode: string | null = null;
    let simulatedError: string | null = null;

    if (pendingUser && pendingUser.id) {
      try {
        const user = await UserModel.findById(pendingUser.id);
        const secret = user?.mfa_secret || user?.mfa_temp_secret;
        if (secret) {
          simulatedCode = generateSync({ secret });
        } else {
          simulatedError = 'No secret found for user ' + pendingUser.id;
        }
      } catch (e: any) {
        simulatedError = e.message || String(e);
      }
    }

    // Defense demonstration fallback: If no active user in session, compute for Praise E. Bello (SCI22CSC073)
    if (!simulatedCode) {
      try {
        const defaultUser = await UserModel.findByMatricOrUsername('SCI22CSC073');
        if (defaultUser?.mfa_secret) {
          simulatedCode = generateSync({ secret: defaultUser.mfa_secret });
        }
      } catch (e) {
        // ignore
      }
    }

    return res.json({
      timeRemaining,
      epochSeconds,
      step,
      simulatedCode
    });
  }
}
