/**
 * Login Attempt Model
 * -------------------
 * Captures granular audit trails for authentication steps:
 * - Password verification (Step 1)
 * - TOTP validation (Step 2)
 * Used to support brute-force defense analytics and thesis presentation demonstrations.
 */

import { dbQuery, dbRun } from './db';

export interface LoginAttempt {
  id: number;
  username: string;
  ip_address: string;
  attempt_type: 'PASSWORD_STEP_1' | 'TOTP_STEP_2';
  status: 'SUCCESS' | 'FAILED';
  failure_reason?: string | null;
  user_agent?: string | null;
  timestamp: string;
}

export class LoginAttemptModel {
  /**
   * Log an authentication attempt
   */
  static async log(data: {
    username: string;
    ip_address: string;
    attempt_type: 'PASSWORD_STEP_1' | 'TOTP_STEP_2';
    status: 'SUCCESS' | 'FAILED';
    failure_reason?: string;
    user_agent?: string;
  }): Promise<number> {
    const result = await dbRun(
      `INSERT INTO login_attempts (username, ip_address, attempt_type, status, failure_reason, user_agent)
       VALUES (?, ?, ?, ?, ?, ?)`,
      [
        data.username || 'unknown',
        data.ip_address || '127.0.0.1',
        data.attempt_type,
        data.status,
        data.failure_reason || null,
        data.user_agent || 'Unknown'
      ]
    );
    return result.lastID;
  }

  /**
   * Fetch recent login attempts for a specific user or system-wide (for dashboard audit panel)
   */
  static async getRecentByUser(username: string, limit = 10): Promise<LoginAttempt[]> {
    return dbQuery<LoginAttempt>(
      `SELECT * FROM login_attempts 
       WHERE LOWER(username) = LOWER(?) 
       ORDER BY id DESC LIMIT ?`,
      [username, limit]
    );
  }

  /**
   * Fetch recent system-wide attempts (for portal security telemetry)
   */
  static async getRecentSystemAttempts(limit = 15): Promise<LoginAttempt[]> {
    return dbQuery<LoginAttempt>(
      `SELECT * FROM login_attempts 
       ORDER BY id DESC LIMIT ?`,
      [limit]
    );
  }
}
