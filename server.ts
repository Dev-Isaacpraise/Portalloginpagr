/**
 * Server Entry Point
 * ------------------
 * Credential Verification Portal for Academic Recruitment
 * Final-Year Thesis Implementation: Multi-Factor Authentication (MFA) via RFC 6238 TOTP
 * 
 * Architecture:
 * - Runtime: Node.js + Express.js
 * - Templating: Server-Rendered EJS Views
 * - Database: SQLite3 (users, login_attempts, academic_records)
 * - Cryptography: bcrypt (passwords), otplib (HMAC-SHA1 RFC 6238 TOTP), qrcode
 * - Defense in Depth: express-rate-limit brute force throttling, session compartmentalization
 */

import express from 'express';
import session from 'express-session';
import path from 'path';
import fs from 'fs';
import { initDatabase } from './models/db';
import authRoutes from './routes/auth.routes';
import mfaRoutes from './routes/mfa.routes';
import portalRoutes from './routes/portal.routes';

const app = express();
const PORT = 3000;

// Trust reverse proxies (important for correct IP extraction in rate limiting and logs)
app.set('trust proxy', 1);

// Configure Paths
const publicPath = path.join(process.cwd(), 'public');
const viewsPath = path.join(process.cwd(), 'views');

// Middleware 1: Static Assets (plain CSS and vanilla JS)
app.use(express.static(publicPath));

// Middleware 2: Request Body Parsing
app.use(express.urlencoded({ extended: true }));
app.use(express.json());

// Middleware 3: View Engine Setup (EJS)
app.set('view engine', 'ejs');
app.set('views', viewsPath);

// Middleware 4: Session Management
// Notice: Session cookies are strictly isolated. A user completing Step 1 is NOT given
// a fully authenticated session until Step 2 (TOTP verification) passes.
app.use(
  session({
    secret: process.env.SESSION_SECRET || 'thesis-mfa-portal-secret-key-fulokoja-2026',
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true, // Mitigates XSS cookie theft
      secure: false,  // Compatible with local and reverse proxy environments
      sameSite: 'lax',
      maxAge: 1000 * 60 * 60 * 2 // 2-hour session lifetime
    }
  })
);

// Debug session logging
app.use((req, res, next) => {
  if (req.path.startsWith('/api/mfa') || req.path === '/mfa/verify' || req.path === '/login') {
    console.log(`[REQ ${req.method} ${req.path}] cookie:`, req.headers.cookie, 'sessionID:', req.sessionID, 'sessionKeys:', Object.keys(req.session || {}));
  }
  next();
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    system: 'Credential Verification Portal with TOTP MFA',
    time: new Date().toISOString()
  });
});

// Mount Modular Routes
app.use('/', authRoutes);
app.use('/', mfaRoutes);
app.use('/', portalRoutes);

// Global 404 Handler
app.use((req, res) => {
  res.status(404).render('login', {
    error: 'The requested portal resource was not found. Please sign in.',
    username: '',
    rateLimited: false
  });
});

// Boot Database and Listen on Required Port 3000
async function startServer() {
  try {
    // Initialize SQLite schema and demo records
    await initDatabase();

    app.listen(PORT, '0.0.0.0', () => {
      console.log(`=======================================================`);
      console.log(`🏛️ Academic Credential Verification Portal (MFA TOTP)`);
      console.log(`📡 Server listening on http://0.0.0.0:${PORT}`);
      console.log(`🔐 Thesis Demo: RFC 6238 Time-based One-Time Passwords`);
      console.log(`=======================================================`);
    });
  } catch (error) {
    console.error('Fatal Server Startup Error:', error);
    process.exit(1);
  }
}

startServer();
