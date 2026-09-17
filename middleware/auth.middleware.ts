/**
 * Authentication Middleware
 * -------------------------
 * Guard middleware enforcing two-step authentication integrity:
 * 1. requireAuth: Session gate protecting /dashboard and protected portal actions.
 * 2. requireMfaPending: Ensures user has successfully validated password (Step 1)
 *    before they can access TOTP input (/mfa/verify).
 * 3. redirectIfAuthenticated: Convenience redirect from login/register to dashboard.
 */

import { Request, Response, NextFunction } from 'express';
import { TicketService } from '../services/ticket.service';

export function requireAuth(req: Request, res: Response, next: NextFunction) {
  // 1. Standard session check
  if (req.session && (req.session as any).user) {
    return next();
  }

  // 2. Ticket fallback (critical for cross-origin iframe environments like AI Studio)
  const authToken = (req.query.auth_token || req.headers['authorization']?.toString().replace('Bearer ', '')) as string;
  if (authToken) {
    const user = TicketService.getAuthTicket(authToken);
    if (user) {
      if (req.session) {
        (req.session as any).user = user;
      }
      (req as any).user = user;
      return next();
    }
  }

  res.redirect('/login?notice=Please+sign+in+to+access+the+portal');
}

export function requireMfaPending(req: Request, res: Response, next: NextFunction) {
  // 1. Standard session check
  if (req.session && (req.session as any).mfaPendingUser) {
    return next();
  }

  // 2. Pending ticket fallback
  const ticket = (req.query.ticket || req.body.ticket) as string;
  if (ticket) {
    const pendingUser = TicketService.getPendingTicket(ticket);
    if (pendingUser) {
      if (req.session) {
        (req.session as any).mfaPendingUser = pendingUser;
      }
      (req as any).mfaPendingUser = pendingUser;
      return next();
    }
  }

  res.redirect('/login?error=Please+complete+step+1+first');
}

export function redirectIfAuthenticated(req: Request, res: Response, next: NextFunction) {
  if (req.session && (req.session as any).user) {
    return res.redirect('/dashboard');
  }
  const authToken = req.query.auth_token as string;
  if (authToken && TicketService.getAuthTicket(authToken)) {
    return res.redirect('/dashboard?auth_token=' + authToken);
  }
  next();
}
