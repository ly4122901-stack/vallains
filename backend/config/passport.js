/**
 * Passport Configuration
 * 
 * OAuth strategies for Google, GitHub, and Facebook
 * Plus local email/password strategy
 */

const passport = require('passport');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

// Load strategies
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const GitHubStrategy = require('passport-github2').Strategy;
const FacebookStrategy = require('passport-facebook').Strategy;
const LocalStrategy = require('passport-local').Strategy;

// Load User model
const User = require('../models/User');

// Environment variables
const {
  GOOGLE_CLIENT_ID,
  GOOGLE_CLIENT_SECRET,
  GOOGLE_CALLBACK_URL,
  GITHUB_CLIENT_ID,
  GITHUB_CLIENT_SECRET,
  GITHUB_CALLBACK_URL,
  FACEBOOK_APP_ID,
  FACEBOOK_APP_SECRET,
  FACEBOOK_CALLBACK_URL,
  JWT_SECRET,
  SESSION_SECRET
} = process.env;

/**
 * Serialize user to session
 */
passport.serializeUser((user, done) => {
  done(null, user.id);
});

/**
 * Deserialize user from session
 */
passport.deserializeUser((id, done) => {
  const user = User.findById(id);
  done(null, user);
});

/**
 * Generate JWT token for user
 */
function generateToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    JWT_SECRET || SESSION_SECRET,
    { expiresIn: '7d' }
  );
}

/**
 * Handle OAuth profile - find or create user
 */
async function handleOAuthProfile(provider, providerId, profile, done) {
  try {
    // Check if user exists with this OAuth account
    let user = User.findByProvider(provider, providerId);
    
    if (user) {
      // Update last login and return
      user.lastLogin = new Date();
      return done(null, user);
    }

    // Check if user exists with same email
    if (profile.email) {
      const existingUser = User.findByEmail(profile.email);
      if (existingUser) {
        // Link OAuth account to existing user
        existingUser.addAccount(provider, providerId, profile);
        return done(null, existingUser);
      }
    }

    // Create new user
    const email = profile.email || `${providerId}@${provider}.com`;
    const displayName = profile.displayName || profile.name || profile.username || 'User';
    
    user = User.create({
      email,
      name: displayName,
      avatar: profile.picture || profile.avatarUrl
    });

    // Link OAuth account
    user.addAccount(provider, providerId, profile);

    return done(null, user);
  } catch (error) {
    return done(error, null);
  }
}

// ============================================
// Google Strategy
// ============================================
if (GOOGLE_CLIENT_ID && GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: GOOGLE_CLIENT_ID,
    clientSecret: GOOGLE_CLIENT_SECRET,
    callbackURL: GOOGLE_CALLBACK_URL || '/auth/google/callback',
    scope: ['email', 'profile']
  }, (accessToken, refreshToken, profile, done) => {
    const profileData = {
      email: profile.emails?.[0]?.value || null,
      displayName: profile.displayName,
      name: profile.name,
      picture: profile.photos?.[0]?.value || null
    };
    
    handleOAuthProfile('google', profile.id, profileData, done);
  }));
}

// ============================================
// GitHub Strategy
// ============================================
if (GITHUB_CLIENT_ID && GITHUB_CLIENT_SECRET) {
  passport.use(new GitHubStrategy({
    clientID: GITHUB_CLIENT_ID,
    clientSecret: GITHUB_CLIENT_SECRET,
    callbackURL: GITHUB_CALLBACK_URL || '/auth/github/callback',
    scope: ['user:email']
  }, (accessToken, refreshToken, profile, done) => {
    // GitHub may not return email in profile, need to fetch from emails
    const emails = profile.emails || [];
    const primaryEmail = emails.find(e => e.primary) || emails[0] || null;
    
    const profileData = {
      email: primaryEmail?.value || null,
      displayName: profile.displayName || profile.username,
      name: profile.name,
      picture: profile.avatarUrl,
      username: profile.username
    };
    
    handleOAuthProfile('github', profile.id, profileData, done);
  }));
}

// ============================================
// Facebook Strategy
// ============================================
if (FACEBOOK_APP_ID && FACEBOOK_APP_SECRET) {
  passport.use(new FacebookStrategy({
    clientID: FACEBOOK_APP_ID,
    clientSecret: FACEBOOK_APP_SECRET,
    callbackURL: FACEBOOK_CALLBACK_URL || '/auth/facebook/callback',
    scope: ['email'],
    profileFields: ['id', 'displayName', 'email', 'name', 'picture']
  }, (accessToken, refreshToken, profile, done) => {
    const profileData = {
      email: profile.emails?.[0]?.value || null,
      displayName: profile.displayName,
      name: profile.name,
      picture: profile.photos?.[0]?.value || null
    };
    
    handleOAuthProfile('facebook', profile.id, profileData, done);
  }));
}

// ============================================
// Local Strategy (Email/Password)
// ============================================
passport.use(new LocalStrategy({
  usernameField: 'email',
  passwordField: 'password'
}, async (email, password, done) => {
  try {
    if (!email || !password) {
      return done(null, false, { message: 'Email and password are required' });
    }

    const user = User.findByEmail(email);
    
    if (!user) {
      return done(null, false, { message: 'Invalid email or password' });
    }

    const isValidPassword = await bcrypt.compare(password, user.password);
    
    if (!isValidPassword) {
      return done(null, false, { message: 'Invalid email or password' });
    }

    user.lastLogin = new Date();
    return done(null, user);
  } catch (error) {
    return done(error, false, { message: 'Authentication failed' });
  }
}));

// Export passport and generateToken
module.exports = { passport, generateToken };