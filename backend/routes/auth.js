const express = require('express');
const passport = require('passport');
const router = express.Router();
const { requireAuth, rateLimitAuth } = require('../middleware/auth');

// Initiate Google OAuth
router.get('/google', rateLimitAuth, passport.authenticate('google'));

// Google OAuth callback
router.get('/google/callback',
  passport.authenticate('google', {
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=google_failed`
  }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/dashboard?welcome=true`);
  }
);

// Initiate GitHub OAuth
router.get('/github', rateLimitAuth, passport.authenticate('github'));

// GitHub OAuth callback
router.get('/github/callback',
  passport.authenticate('github', {
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=github_failed`
  }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/dashboard?welcome=true`);
  }
);

// Initiate Facebook OAuth
router.get('/facebook', rateLimitAuth, passport.authenticate('facebook'));

// Facebook OAuth callback
router.get('/facebook/callback',
  passport.authenticate('facebook', {
    failureRedirect: `${process.env.FRONTEND_URL || 'http://localhost:5173'}/login?error=facebook_failed`
  }),
  (req, res) => {
    res.redirect(`${process.env.FRONTEND_URL || 'http://localhost:5173'}/dashboard?welcome=true`);
  }
);

// Get current user
router.get('/me', requireAuth, (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user.id,
      email: req.user.email,
      name: req.user.name,
      avatar: req.user.avatar,
      provider: req.user.provider
    }
  });
});

// Logout
router.get('/logout', (req, res) => {
  req.logout((err) => {
    if (err) {
      return res.status(500).json({
        success: false,
        error: 'Logout failed'
      });
    }
    req.session.destroy((err) => {
      if (err) {
        console.error('Session destruction error:', err);
      }
      res.json({
        success: true,
        message: 'Logged out successfully'
      });
    });
  });
});

// Check if authenticated
router.get('/status', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      success: true,
      authenticated: true,
      user: {
        id: req.user.id,
        email: req.user.email,
        name: req.user.name,
        avatar: req.user.avatar
      }
    });
  } else {
    res.json({
      success: true,
      authenticated: false
    });
  }
});

module.exports = router;