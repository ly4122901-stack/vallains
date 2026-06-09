/**
 * Scan Engine Service
 * Handles vulnerability scanning operations
 */

// Allowed scan types
const ALLOWED_SCAN_TYPES = [
  'sql-injection',
  'xss',
  'csrf',
  'ssrf',
  'open-redirect',
  'idor',
  'command-injection',
  'xxe',
  'full-port-scan',
  'subdomain-enum'
];

// In-memory scan history storage (in production, use a database)
const scanHistory = new Map();

/**
 * Validate scan type
 * @param {string} type - The scan type to validate
 * @returns {boolean} - Whether the type is valid
 */
function isValidScanType(type) {
  return ALLOWED_SCAN_TYPES.includes(type);
}

/**
 * Get allowed scan types
 * @returns {string[]} - Array of allowed scan types
 */
function getAllowedScanTypes() {
  return [...ALLOWED_SCAN_TYPES];
}

/**
 * Execute a security scan
 * @param {string} target - Target domain or IP
 * @param {string} type - Scan type
 * @param {string} userId - User ID who initiated the scan
 * @returns {Promise<Object>} - Scan results
 */
async function scan(target, type, userId) {
  const startTime = Date.now();
  
  // Simulate scanning process (in production, this would call actual scanning tools)
  await new Promise(resolve => setTimeout(resolve, 100 + Math.random() * 400));
  
  const duration = Date.now() - startTime;
  
  // Generate simulated results based on scan type
  const results = generateSimulatedResults(type, target);
  
  // Calculate summary
  const summary = calculateSummary(results);
  
  const scanResult = {
    success: true,
    target,
    type,
    timestamp: new Date().toISOString(),
    duration,
    results,
    summary
  };
  
  // Store in history
  const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  scanResult.id = scanId;
  scanResult.userId = userId;
  
  // Keep only last 1000 scans in memory
  if (scanHistory.size >= 1000) {
    const firstKey = scanHistory.keys().next().value;
    scanHistory.delete(firstKey);
  }
  scanHistory.set(scanId, scanResult);
  
  return scanResult;
}

/**
 * Generate simulated scan results
 * @param {string} type - Scan type
 * @param {string} target - Target
 * @returns {Object} - Simulated findings
 */
function generateSimulatedResults(type, target) {
  // Simulate different findings based on scan type
  const findings = [];
  const random = Math.random();
  
  if (random > 0.6) {
    findings.push({
      type: 'critical',
      title: `${type.toUpperCase()} Vulnerability Detected`,
      description: `Potential ${type.replace('-', ' ')} vulnerability found`,
      location: `https://${target}/`,
      severity: 'critical',
      cve: `CVE-2024-${Math.floor(Math.random() * 9999).toString().padStart(4, '0')}`
    });
  }
  
  if (random > 0.3) {
    findings.push({
      type: 'high',
      title: 'Security Header Missing',
      description: 'Important security headers are not configured',
      location: `https://${target}/`,
      severity: 'high',
      recommendation: 'Add Strict-Transport-Security, X-Content-Type-Options, X-Frame-Options headers'
    });
  }
  
  if (random > 0.1) {
    findings.push({
      type: 'medium',
      title: 'Information Disclosure',
      description: 'Server version information may be exposed',
      location: `https://${target}/`,
      severity: 'medium',
      recommendation: 'Configure server to hide version headers'
    });
  }
  
  findings.push({
    type: 'info',
    title: 'SSL/TLS Configuration',
    description: 'HTTPS is properly configured',
    location: `https://${target}/`,
    severity: 'info',
    recommendation: 'Continue monitoring SSL/TLS configuration'
  });
  
  return { findings, target, scannedAt: new Date().toISOString() };
}

/**
 * Calculate scan summary
 * @param {Object} results - Scan results
 * @returns {Object} - Summary with counts and grade
 */
function calculateSummary(results) {
  const counts = { critical: 0, high: 0, medium: 0, info: 0 };
  
  results.findings.forEach(finding => {
    const severity = finding.severity?.toLowerCase();
    if (counts.hasOwnProperty(severity)) {
      counts[severity]++;
    }
  });
  
  // Calculate grade based on vulnerabilities found
  let grade;
  const totalIssues = counts.critical + counts.high + counts.medium;
  
  if (counts.critical > 0) {
    grade = 'F';
  } else if (counts.high > 2) {
    grade = 'D';
  } else if (counts.high > 0) {
    grade = 'C';
  } else if (counts.medium > 2) {
    grade = 'B';
  } else if (counts.medium > 0) {
    grade = 'B';
  } else {
    grade = 'A';
  }
  
  return {
    ...counts,
    grade,
    totalFindings: results.findings.length
  };
}

/**
 * Get scan by ID
 * @param {string} scanId - Scan ID
 * @returns {Object|null} - Scan result or null
 */
function getScanById(scanId) {
  return scanHistory.get(scanId) || null;
}

/**
 * Get scan history for a user
 * @param {string} userId - User ID
 * @param {number} limit - Max results
 * @param {number} offset - Offset for pagination
 * @returns {Object[]} - Array of scan results
 */
function getScanHistory(userId, limit = 20, offset = 0) {
  const userScans = [];
  
  for (const [id, scan] of scanHistory) {
    if (scan.userId === userId) {
      userScans.push(scan);
    }
  }
  
  // Sort by timestamp descending (newest first)
  userScans.sort((a, b) => new Date(b.timestamp) - new Date(a.timestamp));
  
  // Apply pagination
  return userScans.slice(offset, offset + limit);
}

/**
 * Store scan result (for database integration)
 * @param {string} userId - User ID
 * @param {Object} scanData - Scan data to store
 * @returns {string} - Scan ID
 */
function storeScanResult(userId, scanData) {
  const scanId = `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  const record = {
    id: scanId,
    userId,
    ...scanData,
    createdAt: new Date().toISOString()
  };
  
  scanHistory.set(scanId, record);
  return scanId;
}

module.exports = {
  scan,
  isValidScanType,
  getAllowedScanTypes,
  getScanById,
  getScanHistory,
  storeScanResult,
  ALLOWED_SCAN_TYPES
};