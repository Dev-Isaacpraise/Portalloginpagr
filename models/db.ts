/**
 * Database Module (SQLite via sql.js)
 * -----------------------------------
 * Credential Verification Portal for Academic Recruitment
 * Thesis Topic: Multi-Factor Authentication (MFA) via RFC 6238 TOTP
 * 
 * Provides an asynchronous wrapper around SQLite for persistent storage of:
 * 1. Users (credentials, bcrypt hashes, TOTP secrets, MFA activation flags)
 * 2. Login Attempts (comprehensive audit logs for security monitoring & rate limiting)
 * 3. Academic Records (candidate credentials for recruitment verification)
 * 
 * Uses official SQLite WebAssembly engine with automatic binary disk serialization
 * to data/portal.db, providing true SQLite file persistence with zero native binary glibc friction.
 */

import initSqlJs from 'sql.js';
import path from 'path';
import fs from 'fs';
import bcrypt from 'bcryptjs';

const DATA_DIR = path.join(process.cwd(), 'data');
if (!fs.existsSync(DATA_DIR)) {
  fs.mkdirSync(DATA_DIR, { recursive: true });
}

const DB_PATH = path.join(DATA_DIR, 'portal.db');

let dbInstance: any = null;

function saveDb() {
  if (dbInstance) {
    const data = dbInstance.export();
    const buffer = Buffer.from(data);
    fs.writeFileSync(DB_PATH, buffer);
  }
}

export async function getDb() {
  if (!dbInstance) {
    const SQL = await initSqlJs();
    if (fs.existsSync(DB_PATH)) {
      try {
        const filebuffer = fs.readFileSync(DB_PATH);
        dbInstance = new SQL.Database(filebuffer);
      } catch (e) {
        console.warn('Existing database unreadable, creating fresh instance.');
        dbInstance = new SQL.Database();
        saveDb();
      }
    } else {
      dbInstance = new SQL.Database();
      saveDb();
    }
  }
  return dbInstance;
}

// Promisified query helpers for async/await usage across models
export const dbQuery = async <T = any>(sql: string, params: any[] = []): Promise<T[]> => {
  const db = await getDb();
  try {
    const stmt = db.prepare(sql);
    if (params && params.length > 0) {
      stmt.bind(params);
    }
    const rows: T[] = [];
    while (stmt.step()) {
      rows.push(stmt.getAsObject() as T);
    }
    stmt.free();
    return rows;
  } catch (err) {
    console.error('SQLite query error:', err, 'SQL:', sql, 'params:', params);
    throw err;
  }
};

export const dbGet = async <T = any>(sql: string, params: any[] = []): Promise<T | undefined> => {
  const rows = await dbQuery<T>(sql, params);
  return rows.length > 0 ? rows[0] : undefined;
};

export const dbRun = async (sql: string, params: any[] = []): Promise<{ lastID: number; changes: number }> => {
  const db = await getDb();
  try {
    if (params && params.length > 0) {
      db.run(sql, params);
    } else {
      db.run(sql);
    }
    const result = db.exec('SELECT last_insert_rowid() AS lastID, changes() AS changes;');
    const lastID = result[0]?.values[0]?.[0] !== undefined ? Number(result[0].values[0][0]) : 0;
    const changes = result[0]?.values[0]?.[1] !== undefined ? Number(result[0].values[0][1]) : 0;
    saveDb();
    return { lastID, changes };
  } catch (err) {
    console.error('SQLite run error:', err, 'SQL:', sql, 'params:', params);
    throw err;
  }
};

/**
 * Initialize Database Tables and Pre-seed Demo Data for Thesis Defense
 */
export async function initDatabase(): Promise<void> {
  await getDb();

  // Check if users table has matric_no column; if not, drop old tables to rebuild fresh
  try {
    const colInfo = await dbQuery("PRAGMA table_info(users)");
    const hasMatric = colInfo.some((col: any) => col.name === 'matric_no');
    if (!hasMatric && colInfo.length > 0) {
      console.log('[SQLite] Migrating schema to institutional Matric No & RRR format...');
      await dbRun("DROP TABLE IF EXISTS academic_records;");
      await dbRun("DROP TABLE IF EXISTS login_attempts;");
      await dbRun("DROP TABLE IF EXISTS users;");
    }
  } catch (e) {
    // Fresh database
  }

  // 1. Users table (Institutional Student & Clearance Authentication)
  await dbRun(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      matric_no TEXT UNIQUE NOT NULL,
      rrr_code TEXT NOT NULL,
      username TEXT UNIQUE NOT NULL,
      email TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      full_name TEXT NOT NULL,
      staff_id TEXT,
      department TEXT NOT NULL,
      faculty TEXT NOT NULL DEFAULT 'Faculty of Science',
      level TEXT NOT NULL DEFAULT '400 Level',
      role TEXT NOT NULL DEFAULT 'Undergraduate Student',
      mfa_secret TEXT,
      mfa_temp_secret TEXT,
      mfa_enabled INTEGER NOT NULL DEFAULT 0,
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // 2. Login attempts audit table
  await dbRun(`
    CREATE TABLE IF NOT EXISTS login_attempts (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT,
      ip_address TEXT,
      attempt_type TEXT NOT NULL,
      status TEXT NOT NULL,
      failure_reason TEXT,
      user_agent TEXT,
      timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // 3. Academic recruitment verified records table
  await dbRun(`
    CREATE TABLE IF NOT EXISTS academic_records (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      qualification TEXT NOT NULL,
      institution TEXT NOT NULL,
      grade_or_class TEXT NOT NULL,
      completion_year INTEGER NOT NULL,
      credential_hash TEXT NOT NULL,
      verification_status TEXT NOT NULL DEFAULT 'VERIFIED',
      created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    );
  `);

  // Seed sample users for immediate evaluation & presentation
  await seedInitialData();
}

/**
 * Seeds institutional student accounts:
 * 1. SCI22CSC073 / QW23456H (Praise E. Bello): MFA active for instant demonstration of login Step 2
 * 2. SCI22CSC099 / RM884920K (Adeola Adeleke): Fresh student with MFA unconfigured for QR code enrollment
 */
async function seedInitialData() {
  const existingUser = await dbGet('SELECT id FROM users WHERE matric_no = ? OR username = ?', ['SCI22CSC073', 'SCI22CSC073']);
  if (!existingUser) {
    const rrrSecretPraise = 'QW23456H';
    const passwordHashPraise = await bcrypt.hash(rrrSecretPraise, 10);

    // Standard 160-bit Base32 secret for Praise E. Bello
    const seededSecret = 'JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP';

    const result = await dbRun(
      `INSERT INTO users (matric_no, rrr_code, username, email, password_hash, full_name, staff_id, department, faculty, level, role, mfa_secret, mfa_enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 1)`,
      [
        'SCI22CSC073',
        'QW23456H',
        'SCI22CSC073',
        'praise.bello@fulokoja.edu.ng',
        passwordHashPraise,
        'Praise E. Bello',
        'SCI22CSC073',
        'Computer Science',
        'Faculty of Science',
        '400 Level (Final Year)',
        'Undergraduate Researcher',
        seededSecret
      ]
    );

    const userId = result.lastID;

    // Seed academic clearance records for SCI22CSC073
    await dbRun(
      `INSERT INTO academic_records (user_id, qualification, institution, grade_or_class, completion_year, credential_hash, verification_status)
       VALUES 
       (?, 'CSC 401: Cryptography & Network Security', 'Federal University Lokoja', 'Grade A (5.0)', 2026, 'SHA256: 7f83b1657ff1fc53b92dc18148a1d65dfc2d4b1fa3d677284addd200126d9069', 'VERIFIED'),
       (?, 'CSC 411: Artificial Intelligence & Expert Systems', 'Federal University Lokoja', 'Grade A (5.0)', 2026, 'SHA256: 185f8db32271fe25f561a6fc938b2e264306ec304eda518007d1764826381969', 'VERIFIED'),
       (?, 'CSC 301: Database Design & Management Systems', 'Federal University Lokoja', 'Grade A (5.0)', 2025, 'SHA256: e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855', 'VERIFIED'),
       (?, 'Remita Tuition & Clearance Verification Slip', 'Federal University Lokoja (Bursary)', 'RRR: QW23456H (Paid)', 2026, 'SHA256: a591a6d40bf420404a011733cfb7b190d62c65bf0bcda32b57b277d9ad9f146e', 'VERIFIED')`,
      [userId, userId, userId, userId]
    );

    // Seed realistic audit log entries
    const sampleIps = ['192.168.1.45', '102.89.23.114', '197.210.55.90'];
    await dbRun(
      `INSERT INTO login_attempts (username, ip_address, attempt_type, status, failure_reason, user_agent)
       VALUES 
       ('SCI22CSC073', ?, 'PASSWORD_STEP_1', 'SUCCESS', NULL, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
       ('SCI22CSC073', ?, 'TOTP_STEP_2', 'SUCCESS', NULL, 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)'),
       ('SCI22CSC073', ?, 'PASSWORD_STEP_1', 'FAILED', 'Invalid RRR clearance reference', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
       ('SCI22CSC073', ?, 'PASSWORD_STEP_1', 'SUCCESS', NULL, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
       ('SCI22CSC073', ?, 'TOTP_STEP_2', 'FAILED', 'Invalid 6-digit TOTP token', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)'),
       ('SCI22CSC073', ?, 'TOTP_STEP_2', 'SUCCESS', NULL, 'Mozilla/5.0 (Windows NT 10.0; Win64; x64)')`,
      [sampleIps[0], sampleIps[0], sampleIps[1], sampleIps[1], sampleIps[1], sampleIps[1]]
    );

    // Also seed a student without MFA configured to allow testing the fresh MFA setup flow
    const rrrAdeola = 'RM884920K';
    const passwordHashAdeola = await bcrypt.hash(rrrAdeola, 10);
    const unconfiguredUser = await dbRun(
      `INSERT INTO users (matric_no, rrr_code, username, email, password_hash, full_name, staff_id, department, faculty, level, role, mfa_enabled)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0)`,
      [
        'SCI22CSC099',
        'RM884920K',
        'SCI22CSC099',
        'adeola.adeleke@fulokoja.edu.ng',
        passwordHashAdeola,
        'Adeola K. Adeleke',
        'SCI22CSC099',
        'Computer Science',
        'Faculty of Science',
        '300 Level',
        'Undergraduate Student'
      ]
    );

    await dbRun(
      `INSERT INTO academic_records (user_id, qualification, institution, grade_or_class, completion_year, credential_hash, verification_status)
       VALUES 
       (?, 'CSC 301: Database Design & Management', 'Federal University Lokoja', 'Grade B (4.0)', 2025, 'SHA256: 3c07408562bedb8b60ce05c1decfe3ad16b72230967de01f640b7e4729b49fca', 'VERIFIED'),
       (?, 'Remita Tuition & Clearance Verification Slip', 'Federal University Lokoja (Bursary)', 'RRR: RM884920K (Paid)', 2026, 'SHA256: 8d86b273ff34fce19d6b804eff5a3f5747ada4eaa22f1d49c01e52ddb7875b4c', 'VERIFIED')`,
      [unconfiguredUser.lastID, unconfiguredUser.lastID]
    );

    console.log('[SQLite] Seeded student accounts: "SCI22CSC073" (MFA active) & "SCI22CSC099" (MFA enrollment pending)');
  }
}
