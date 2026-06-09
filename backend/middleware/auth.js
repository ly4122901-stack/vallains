/**
 * JWT Authentication Middleware
 * 
 * Validates JWT tokens and attaches user to request
 */

const jwt = require('jsonwebtoken');
const User = require('../models/User');

const { JWT_SECRET, SESSION_SECRET } = process.env;
const SECRET = JWT_SECRET || SESSION_SECRET;

/**
 * Protect routes - require valid JWT
 */
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ 
      error: true, 
      message: 'Authentication required' 
    });
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, SECRET);
    const user = User.findById(decoded.userId);
    
    if (!user) {
      return res.status(401).json({ 
        error: true, 
        message: 'User not found' 
      });
    }
    
    req.user = user;
    req.token = token;
    next();
  } catch (error) {
    if (error.name === 'TokenExpiredError') {
      return res.status(401).json({ 
        error: true, 
        message: 'Token expired' 
      });
    }
    return res.status(401).json({ 
      error: true, 
      message: 'Invalid token' 
    });
  }
}

/**
 * Optional auth - attach user if token valid, but don't block
 */
function optionalAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next();
  }
  
  const token = authHeader.substring(7);
  
  try {
    const decoded = jwt.verify(token, SECRET);
    const user = User.findById(decoded.userId);
    
    if (user) {
      req.user = user;
      req.token = token;
    }
  } catch (error) {
    // Ignore invalid tokens for optional auth
  }
  
  next();
}

/**
 * Generate token for user (utility function)
 */
function generateToken(user) {
  return jwt.sign(
    { userId: user.id, email: user.email },
    SECRET,
    { expiresIn: '7d' }
  );
}

module.exports = { requireAuth, optionalAuth, generateToken };