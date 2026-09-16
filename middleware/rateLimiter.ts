/**
 * Rate Limiting Middleware
 * ------------------------
 * Protects against brute-force attacks on:
 * 1. Password verification (/login)
 * 2. TOTP 6-digit verification (/mfa/verify and /mfa/confirm)
 * 
 * Thesis defense context:
 * A 6-digit TOTP token has only 1,000,000 possibilities. Without rate limiting,
 * an automated adversary could brute-force the code within the 30-second window.
 * This middleware restricts attempts to 5 per 15-minute window per IP.
 */

import rateLimit from 'express-rate-limit';
import { Request, Response } from 'express';

export const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute cooldown window
  max: 5, // Limit each IP to 5 failed attempts per window
  standardHeaders: true, // Return rate limit info in `RateLimit-*` headers
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Only failed attempts count toward lock-out!
  handler: (req: Request, res: Response) => {
    const retryMinutes = Math.ceil(15);
    // If request accepts JSON or expects HTML
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(429).json({
        success: false,
        error: `Too many failed login attempts from this IP. Account locked for ${retryMinutes} minutes as a security precaution against brute-force attacks.`
      });
    }
    return res.status(429).render('login', {
      error: `Security Alert: Too many failed login attempts. Access temporarily restricted for ${retryMinutes} minutes. Please try again later.`,
      username: req.body?.username || '',
      rateLimited: true
    });
  }
});

export const mfaRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15-minute cooldown
  max: 5, // Lockout after 5 failed 6-digit OTP attempts
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: true, // Successful OTP entries don't penalize
  handler: (req: Request, res: Response) => {
    if (req.xhr || req.headers.accept?.includes('application/json')) {
      return res.status(429).json({
        success: false,
        error: 'Too many invalid TOTP code attempts. Multi-factor verification locked for 15 minutes.'
      });
    }
    return res.status(429).render('mfa-verify', {
      error: 'Security Lockout: Too many incorrect 6-digit codes entered. Verification is locked for 15 minutes to prevent automated code enumeration.',
      username: (req.session as any)?.mfaPendingUser?.username || 'User',
      secretSnippet: (req.session as any)?.mfaPendingUser?.secretSnippet || '',
      rateLimited: true
    });
  }
});
