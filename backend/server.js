require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const session = require('express-session');
const passport = require('passport');
const path = require('path');
const http = require('http');
const { Server } = require('socket.io');

// Import configs
const configurePassport = require('./config/passport');
const { initDatabase } = require('./config/database');

// Import middleware
const { rateLimiter, strictRateLimiter, scanRateLimiter, ipBlocker, timeoutMiddleware } = require('./middleware/ddos-protection');

// Import routes
const authRoutes = require('./routes/auth');
const apiRoutes = require('./routes/api');

const app = express();
const server = http.createServer(app);
const io = new Server(server, {
  cors: {
    origin: process.env.FRONTEND_URL || 'http://localhost:5173',
    methods: ['GET', 'POST'],
    credentials: true
  }
});

// Make io accessible to routes
app.set('io', io);

// ========== SECURITY MIDDLEWARE ==========

// Security headers with CSP
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'", "https://fonts.googleapis.com"],
      fontSrc: ["'self'", "https://fonts.gstatic.com"],
      scriptSrc: ["'self'", "'unsafe-inline'"],
      imgSrc: ["'self'", "data:", "https:"],
      connectSrc: ["'self'", "https://accounts.google.com", "https://oauth/"]
    }
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true
  }
}));

// CORS configuration
app.use(cors({
  origin: process.env.FRONTEND_URL || 'http://localhost:5173',
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));

// ========== DDoS PROTECTION ==========

// Global rate limiter - 100 requests per minute per IP
app.use(rateLimiter({
  windowMs: 60000,
  maxRequests: 100,
  message: 'Too many requests. Please slow down.'
}));

// Timeout for slow connections
app.use(timeoutMiddleware({ timeout: 30000 }));

// Body parsing with size limit
app.use(express.json({ limit: '100kb' }));
app.use(express.urlencoded({ extended: true, limit: '100kb' }));

// Session configuration
app.use(session({
  secret: process.env.SESSION_SECRET || 'dev-secret-change-in-production',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: process.env.NODE_ENV === 'production',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
    sameSite: 'lax'
  }
}));

// Initialize Passport
app.use(passport.initialize());
app.use(passport.session());

// Initialize database
initDatabase();

// Configure Passport strategies
configurePassport();

// ========== ROUTES ==========

// Auth routes
app.use('/auth', authRoutes);

// API routes with rate limiting
app.use('/api', strictRateLimiter(), apiRoutes);

// Scan endpoint with extra protection
app.post('/api/scan', scanRateLimiter(), require('../middleware/auth').requireAuth, async (req, res) => {
  const scanEngine = require('./services/scan-engine');
  try {
    const { target, options } = req.body;
    
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target is required'
      });
    }

    // Validate target format
    const urlPattern = /^([a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$/;
    if (!urlPattern.test(target)) {
      return res.status(400).json({
        success: false,
        error: 'Invalid target format. Please enter a valid domain.'
      });
    }

    const io = req.app.get('io');
    const result = await scanEngine.startScan(target, options, io, req.user.id);

    res.json({
      success: true,
      scanId: result.scanId,
      status: result.status
    });
  } catch (err) {
    console.error('Scan error:', err);
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Serve static files (frontend production build)
const publicPath = path.join(__dirname, 'public');
app.use(express.static(publicPath));

// SPA fallback - serve index.html for non-API routes
app.get(/^\/(?!auth|api).*/, (req, res) => {
  res.sendFile(path.join(publicPath, 'index.html'));
});

// ========== ERROR HANDLING ==========

// Error handling middleware
app.use((err, req, res, next) => {
  console.error('Error:', err.message);
  
  const statusCode = err.statusCode || 500;
  const message = process.env.NODE_ENV === 'production' 
    ? 'Internal server error' 
    : err.message;
  
  res.status(statusCode).json({
    success: false,
    error: message,
    ...(process.env.NODE_ENV !== 'production' && { stack: err.stack })
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Resource not found'
  });
});

// ========== SOCKET.IO ==========

io.on('connection', (socket) => {
  console.log('Client connected:', socket.id);
  
  // Rate limit socket connections
  socket.on('join', (userId) => {
    // Join user-specific room for targeted updates
    socket.join(`user:${userId}`);
  });
  
  socket.on('disconnect', () => {
    console.log('Client disconnected:', socket.id);
  });
});

// ========== START SERVER ==========

const PORT = process.env.PORT || 3000;
server.listen(PORT, () => {
  console.log(`🔥 Vallains Security Scanner running on port ${PORT}`);
  console.log(`📡 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`🛡️ DDoS Protection: Enabled`);
  console.log(`⚡ Rate Limit: 100 requests/minute`);
});

module.exports = { app, server, io };