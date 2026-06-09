/**
 * DDoS Protection & Rate Limiting Middleware
 */

// In-memory store for rate limiting
const rateLimitStore = new Map();

// Clean up old entries every minute
setInterval(() => {
  const now = Date.now();
  for (const [key, data] of rateLimitStore.entries()) {
    if (now - data.windowStart > 60000) {
      rateLimitStore.delete(key);
    }
  }
}, 60000);

/**
 * Rate limiter middleware
 * @param {Object} options - Configuration options
 */
function rateLimiter(options = {}) {
  const {
    windowMs = 60000, // 1 minute window
    maxRequests = 100, // max requests per window
    message = 'Too many requests, please try again later'
  } = options;
  
  return (req, res, next) => {
    const key = req.ip || req.connection.remoteAddress;
    const now = Date.now();
    
    let record = rateLimitStore.get(key);
    
    if (!record || now - record.windowStart > windowMs) {
      // Start new window
      record = {
        count: 1,
        windowStart: now
      };
      rateLimitStore.set(key, record);
    } else {
      record.count++;
    }
    
    // Set rate limit headers
    res.set({
      'X-RateLimit-Limit': maxRequests,
      'X-RateLimit-Remaining': Math.max(0, maxRequests - record.count),
      'X-RateLimit-Reset': Math.ceil((record.windowStart + windowMs) / 1000)
    });
    
    if (record.count > maxRequests) {
      return res.status(429).json({
        success: false,
        error: message,
        retryAfter: Math.ceil((record.windowStart + windowMs - now) / 1000)
      });
    }
    
    next();
  };
}

/**
 * Strict rate limiter for sensitive endpoints
 */
function strictRateLimiter(options = {}) {
  const {
    windowMs = 60000,
    maxRequests = 10,
    message = 'Rate limit exceeded for this operation'
  } = options;
  
  return rateLimiter({ windowMs, maxRequests, message });
}

/**
 * Scan rate limiter - prevents abuse of scan functionality
 */
function scanRateLimiter() {
  const scanLimits = new Map();
  
  return (req, res, next) => {
    const userId = req.user?.id || req.ip;
    const now = Date.now();
    
    let userLimit = scanLimits.get(userId);
    
    if (!userLimit || now - userLimit.windowStart > 60000) {
      userLimit = { count: 0, windowStart: now, scans: [] };
      scanLimits.set(userId, userLimit);
    }
    
    // Max 10 scans per minute
    if (userLimit.count >= 10) {
      return res.status(429).json({
        success: false,
        error: 'Maximum scans per minute exceeded. Please wait before scanning again.',
        retryAfter: Math.ceil((userLimit.windowStart + 60000 - now) / 1000)
      });
    }
    
    // Max 50 scans per hour
    const hourAgo = now - 3600000;
    userLimit.scans = userLimit.scans.filter(t => t > hourAgo);
    
    if (userLimit.scans.length >= 50) {
      return res.status(429).json({
        success: false,
        error: 'Maximum hourly scans exceeded. Please try again later.',
        retryAfter: Math.ceil((userLimit.scans[0] + 3600000 - now) / 1000)
      });
    }
    
    userLimit.count++;
    userLimit.scans.push(now);
    
    next();
  };
}

/**
 * IP blacklist checker
 */
const blacklist = new Set();

function addToBlacklist(ip) {
  blacklist.add(ip);
}

function removeFromBlacklist(ip) {
  blacklist.delete(ip);
}

function isBlacklisted(ip) {
  return blacklist.has(ip);
}

function ipBlocker(req, res, next) {
  const ip = req.ip || req.connection.remoteAddress;
  
  if (isBlacklisted(ip)) {
    return res.status(403).json({
      success: false,
      error: 'Access denied'
    });
  }
  
  next();
}

/**
 * User agent blocker - blocks known bots and scrapers
 */
function userAgentBlocker(req, res, next) {
  const userAgent = req.headers['user-agent'] || '';
  
  const blockedPatterns = [
    /curl/i,
    /wget/i,
    /python-requests/i,
    /scrapy/i,
    /nmap/i,
    /masscan/i,
    /sqlmap/i,
    /burp/i,
    /zap/i
  ];
  
  // Allow these with proper authentication
  if (req.user) {
    return next();
  }
  
  // Block suspicious user agents without auth
  for (const pattern of blockedPatterns) {
    if (pattern.test(userAgent) && !req.user) {
      return res.status(403).json({
        success: false,
        error: 'Access denied'
      });
    }
  }
  
  next();
}

/**
 * Request size limiter
 */
function requestSizeLimiter(options = {}) {
  const { maxSize = '1mb' } = options;
  
  return express.json({ limit: maxSize });
}

/**
 * Timeout middleware for slow clients
 */
function timeoutMiddleware(options = {}) {
  const { timeout = 30000 } = options;
  
  return (req, res, next) => {
    req.setTimeout(timeout);
    res.setTimeout(timeout);
    next();
  };
}

module.exports = {
  rateLimiter,
  strictRateLimiter,
  scanRateLimiter,
  ipBlocker,
  userAgentBlocker,
  addToBlacklist,
  removeFromBlacklist,
  isBlacklisted
};