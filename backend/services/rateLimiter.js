/**
 * Rate Limiter Service
 * Tracks scan requests per user and enforces rate limits
 */

// In-memory rate limit tracking
const rateLimitStore = new Map();

// Rate limit configuration
const RATE_LIMIT = {
  maxScans: 10,
  windowMs: 60 * 1000 // 1 minute in milliseconds
};

/**
 * Check if user is rate limited
 * @param {string} userId - User ID
 * @returns {Object} - { allowed: boolean, remaining: number, resetTime: number }
 */
function checkRateLimit(userId) {
  const now = Date.now();
  const key = `rate:${userId}`;
  
  let userRateData = rateLimitStore.get(key);
  
  // Initialize or reset if window expired
  if (!userRateData || now - userRateData.windowStart > RATE_LIMIT.windowMs) {
    userRateData = {
      windowStart: now,
      count: 0
    };
    rateLimitStore.set(key, userRateData);
  }
  
  const allowed = userRateData.count < RATE_LIMIT.maxScans;
  const remaining = Math.max(0, RATE_LIMIT.maxScans - userRateData.count);
  const resetTime = userRateData.windowStart + RATE_LIMIT.windowMs;
  
  return { allowed, remaining, resetTime, currentCount: userRateData.count };
}

/**
 * Record a scan request for a user
 * @param {string} userId - User ID
 * @returns {Object} - Updated rate limit status
 */
function recordScanRequest(userId) {
  const key = `rate:${userId}`;
  const now = Date.now();
  
  let userRateData = rateLimitStore.get(key);
  
  // Initialize or reset if window expired
  if (!userRateData || now - userRateData.windowStart > RATE_LIMIT.windowMs) {
    userRateData = {
      windowStart: now,
      count: 0
    };
  }
  
  userRateData.count++;
  rateLimitStore.set(key, userRateData);
  
  return {
    allowed: true,
    remaining: Math.max(0, RATE_LIMIT.maxScans - userRateData.count),
    resetTime: userRateData.windowStart + RATE_LIMIT.windowMs,
    currentCount: userRateData.count
  };
}

/**
 * Get current rate limit status for a user
 * @param {string} userId - User ID
 * @returns {Object} - Current rate limit status
 */
function getRateLimitStatus(userId) {
  return checkRateLimit(userId);
}

/**
 * Clear rate limit for a user (admin function)
 * @param {string} userId - User ID
 */
function clearRateLimit(userId) {
  const key = `rate:${userId}`;
  rateLimitStore.delete(key);
}

/**
 * Clean up expired rate limit entries (call periodically)
 */
function cleanupExpiredEntries() {
  const now = Date.now();
  
  for (const [key, data] of rateLimitStore) {
    if (now - data.windowStart > RATE_LIMIT.windowMs * 2) {
      rateLimitStore.delete(key);
    }
  }
}

// Cleanup every 5 minutes
setInterval(cleanupExpiredEntries, 5 * 60 * 1000);

module.exports = {
  checkRateLimit,
  recordScanRequest,
  getRateLimitStatus,
  clearRateLimit,
  RATE_LIMIT
};