/**
 * Vallains Backend - Main Entry Point
 * 
 * Express server with OAuth authentication
 */

require('dotenv').config();

const express = require('express');
const session = require('express-session');
const cors = require('cors');
const passport = require('passport');

const { passport: passportConfig } = require('./config/passport');
const authRoutes = require('./routes/auth');
const { requireAuth } = require('./middleware/auth');

const app = express();
const PORT = process.env.PORT || 3000;
const FRONTEND_URL = process.env.FRONTEND_URL || 'http://localhost:5173';

// ============================================
// Middleware
// ============================================

// CORS
app.use(cors({
  origin: FRONTEND_URL,
  credentials: true
}));

// Body parsing
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Session (required for passport)
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// ============================================
// Routes
// ============================================

// Auth routes
app.use('/', authRoutes);

// Example protected route
app.get('/api/protected', requireAuth, (req, res) => {
  res.json({
    success: true,
    message: 'You have accessed a protected route',
    user: req.user.toPublicJSON()
  });
});

// Health check
app.get('/health', (req, res) => {
  res.json({ 
    status: 'ok', 
    timestamp: new Date().toISOString(),
    auth: {
      google: !!(process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET),
      github: !!(process.env.GITHUB_CLIENT_ID && process.env.GITHUB_CLIENT_SECRET),
      facebook: !!(process.env.FACEBOOK_APP_ID && process.env.FACEBOOK_APP_SECRET)
    }
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({ error: true, message: 'Not found' });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Server error:', err);
  res.status(500).json({ error: true, message: 'Internal server error' });
});

// ============================================
// Start Server
// ============================================

app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════════════════════════╗
║                   Vallains Backend Server                     ║
╠══════════════════════════════════════════════════════════════╣
║  Status:     Running                                         ║
║  Port:       ${PORT}                                           ║
║  Frontend:   ${FRONTEND_URL}                              ║
╠══════════════════════════════════════════════════════════════╣
║  OAuth Providers:                                            ║
║    Google:   ${(process.env.GOOGLE_CLIENT_ID ? '✓ Configured' : '○ Not set')}                                ║
║    GitHub:   ${(process.env.GITHUB_CLIENT_ID ? '✓ Configured' : '○ Not set')}                                ║
║    Facebook: ${(process.env.FACEBOOK_APP_ID ? '✓ Configured' : '○ Not set')}                                ║
╠══════════════════════════════════════════════════════════════╣
║  Auth Endpoints:                                             ║
║    GET  /auth/google        - Start Google OAuth             ║
║    GET  /auth/google/callback - Google OAuth callback         ║
║    GET  /auth/github        - Start GitHub OAuth              ║
║    GET  /auth/github/callback - GitHub OAuth callback         ║
║    GET  /auth/facebook      - Start Facebook OAuth            ║
║    GET  /auth/facebook/callback - Facebook OAuth callback     ║
║    POST /auth/login         - Local login                    ║
║    POST /auth/register      - Local registration              ║
║    GET  /auth/logout        - Logout                          ║
║    GET  /auth/session       - Get current user                ║
║    GET  /auth/accounts      - Get linked OAuth accounts       ║
╚══════════════════════════════════════════════════════════════╝
  `);
});

module.exports = app;