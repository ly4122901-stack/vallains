const { v4: uuidv4 } = require('uuid');

// In-memory scan storage
const scans = new Map();

// Default scan options - includes ALL vulnerability types
const defaultOptions = {
  // Info gathering
  dns: true,
  geoip: true,
  whois: true,
  
  // Security checks
  ssl: true,
  ports: true,
  headers: true,
  
  // Vulnerability scanning
  'sql-injection': true,
  'xss': true,
  'open-redirect': true,
  'ssrf': true,
  'directory-traversal': true,
  'cmdi': true,
  'cors-misconfig': true,
  'xxe': true,
  
  // Discovery
  subdomains: true,
  blacklist: true,
  redirects: true,
  reputation: true
};

/**
 * Start a new comprehensive scan
 * @param {string} target - Target domain or IP
 * @param {object} options - Scan options
 * @param {object} io - Socket.io instance
 * @param {string} userId - User ID
 */
async function startScan(target, options = {}, io, userId) {
  const scanId = uuidv4();
  const scanOptions = { ...defaultOptions, ...options };
  
  const scan = {
    id: scanId,
    target,
    options: scanOptions,
    userId,
    status: 'running',
    progress: 0,
    results: {},
    startedAt: new Date().toISOString(),
    completedAt: null,
    errors: [],
    summary: {
      critical: 0,
      high: 0,
      medium: 0,
      info: 0,
      grade: 'A'
    }
  };
  
  scans.set(scanId, scan);
  
  // Run scan asynchronously
  runScan(scan, io).catch(err => {
    scan.errors.push(err.message);
    scan.status = 'failed';
  });
  
  return { scanId, status: 'started' };
}

/**
 * Run the comprehensive scan process
 */
async function runScan(scan, io) {
  const emit = (event, data) => {
    if (io) io.to(scan.userId).emit(event, data);
  };
  
  const updateProgress = (step, progress, status = 'running') => {
    scan.progress = progress;
    emit('scan:progress', { scanId: scan.id, step, status, progress });
  };
  
  const addVulnerability = (vuln) => {
    if (!scan.results.vulnerabilities) scan.results.vulnerabilities = [];
    scan.results.vulnerabilities.push(vuln);
    
    // Update summary counts
    const severity = vuln.severity || 'info';
    if (scan.summary[severity] !== undefined) {
      scan.summary[severity]++;
    }
  };
  
  try {
    // ========== INFO GATHERING PHASE (0-20%) ==========
    
    if (scan.options.dns) {
      updateProgress('dns', 5);
      const dnsResolver = require('./dns-resolver');
      scan.results.dns = await dnsResolver.lookup(scan.target);
      updateProgress('dns', 10, 'complete');
    }
    
    if (scan.options.geoip) {
      updateProgress('geoip', 12);
      const geoipService = require('./geoip');
      scan.results.geoip = await geoipService.lookup(scan.target);
      updateProgress('geoip', 15, 'complete');
    }
    
    // ========== SECURITY CHECKS PHASE (15-35%) ==========
    
    if (scan.options.ssl) {
      updateProgress('ssl', 17);
      const sslChecker = require('./ssl-checker');
      scan.results.ssl = await sslChecker.check(scan.target, 443);
      updateProgress('ssl', 20, 'complete');
    }
    
    if (scan.options.headers) {
      updateProgress('headers', 22);
      scan.results.securityHeaders = await checkSecurityHeaders(scan.target);
      updateProgress('headers', 25, 'complete');
    }
    
    if (scan.options.ports) {
      updateProgress('ports', 27);
      const portScanner = require('./port-scanner');
      scan.results.ports = await portScanner.scan(scan.target, null, 2000, io);
      updateProgress('ports', 30, 'complete');
    }
    
    // ========== VULNERABILITY SCANNING PHASE (30-70%) ==========
    
    if (scan.options['sql-injection']) {
      updateProgress('sql-injection', 35);
      const sqlScanner = require('./scanners/sql-injection');
      const result = await sqlScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'high';
          v.name = 'SQL Injection';
          addVulnerability(v);
        });
      }
      scan.results.sqlInjection = result;
      updateProgress('sql-injection', 40, 'complete');
    }
    
    if (scan.options['xss']) {
      updateProgress('xss', 42);
      const xssScanner = require('./scanners/xss');
      const result = await xssScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'high';
          v.name = 'Cross-Site Scripting (XSS)';
          addVulnerability(v);
        });
      }
      scan.results.xss = result;
      updateProgress('xss', 47, 'complete');
    }
    
    if (scan.options['open-redirect']) {
      updateProgress('open-redirect', 49);
      const orScanner = require('./scanners/open-redirect');
      const result = await orScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'medium';
          v.name = 'Open Redirect';
          addVulnerability(v);
        });
      }
      scan.results.openRedirect = result;
      updateProgress('open-redirect', 53, 'complete');
    }
    
    if (scan.options['ssrf']) {
      updateProgress('ssrf', 55);
      const ssrfScanner = require('./scanners/ssrf');
      const result = await ssrfScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'high';
          v.name = 'Server-Side Request Forgery (SSRF)';
          addVulnerability(v);
        });
      }
      scan.results.ssrf = result;
      updateProgress('ssrf', 58, 'complete');
    }
    
    if (scan.options['directory-traversal']) {
      updateProgress('directory-traversal', 60);
      const dtScanner = require('./scanners/directory-traversal');
      const result = await dtScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'critical';
          v.name = 'Directory Traversal';
          addVulnerability(v);
        });
      }
      scan.results.directoryTraversal = result;
      updateProgress('directory-traversal', 63, 'complete');
    }
    
    if (scan.options['cmdi']) {
      updateProgress('cmdi', 65);
      const cmdiScanner = require('./scanners/cmdi');
      const result = await cmdiScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'critical';
          v.name = 'Command Injection';
          addVulnerability(v);
        });
      }
      scan.results.cmdi = result;
      updateProgress('cmdi', 68, 'complete');
    }
    
    if (scan.options['cors-misconfig']) {
      updateProgress('cors', 70);
      const corsScanner = require('./scanners/cors-misconfig');
      const result = await corsScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'medium';
          v.name = 'CORS Misconfiguration';
          addVulnerability(v);
        });
      }
      scan.results.cors = result;
      updateProgress('cors', 72, 'complete');
    }
    
    if (scan.options['xxe']) {
      updateProgress('xxe', 74);
      const xxeScanner = require('./scanners/xxe');
      const result = await xxeScanner.scan({ url: `https://${scan.target}`, params: {}, method: 'GET' });
      if (result.vulnerable) {
        result.vulnerabilities.forEach(v => {
          v.severity = 'critical';
          v.name = 'XML External Entity (XXE)';
          addVulnerability(v);
        });
      }
      scan.results.xxe = result;
      updateProgress('xxe', 76, 'complete');
    }
    
    // ========== DISCOVERY PHASE (75-90%) ==========
    
    if (scan.options.subdomains) {
      updateProgress('subdomains', 78);
      const subdomainFinder = require('./subdomain-finder');
      scan.results.subdomains = await subdomainFinder.find(scan.target, null, io);
      updateProgress('subdomains', 82, 'complete');
    }
    
    if (scan.options.blacklist) {
      updateProgress('blacklist', 84);
      const blacklistChecker = require('./blacklist-checker');
      scan.results.blacklist = await blacklistChecker.check(scan.target);
      updateProgress('blacklist', 87, 'complete');
    }
    
    if (scan.options.redirects) {
      updateProgress('redirects', 88);
      scan.results.redirects = await checkRedirects(scan.target);
      updateProgress('redirects', 90, 'complete');
    }
    
    if (scan.options.reputation) {
      updateProgress('reputation', 91);
      scan.results.reputation = await checkReputation(scan.target);
      updateProgress('reputation', 93, 'complete');
    }
    
    // ========== FINALIZE ==========
    
    // Calculate overall grade
    scan.summary.grade = calculateGrade(scan.summary);
    
    scan.status = 'completed';
    scan.progress = 100;
    scan.completedAt = new Date().toISOString();
    
    emit('scan:complete', { 
      scanId: scan.id, 
      results: scan.results,
      summary: scan.summary
    });
    
  } catch (err) {
    scan.status = 'failed';
    scan.errors.push(err.message);
    emit('scan:error', { scanId: scan.id, error: err.message });
    throw err;
  }
}

/**
 * Check security headers
 */
async function checkSecurityHeaders(target) {
  const axios = require('axios');
  const headers = ['Content-Security-Policy', 'X-Frame-Options', 'X-Content-Type-Options', 
    'X-XSS-Protection', 'Strict-Transport-Security', 'Referrer-Policy', 'Permissions-Policy'];
  
  try {
    const response = await axios.get(`https://${target}`, { timeout: 10000 });
    const responseHeaders = response.headers || {};
    
    const results = {
      present: [],
      missing: []
    };
    
    headers.forEach(header => {
      const key = Object.keys(responseHeaders).find(k => k.toLowerCase() === header.toLowerCase());
      if (key) {
        results.present.push({ name: header, value: responseHeaders[key] });
      } else {
        results.missing.push(header);
      }
    });
    
    return results;
  } catch (err) {
    return { present: [], missing: headers, error: err.message };
  }
}

/**
 * Check redirects chain
 */
async function checkRedirects(target) {
  const axios = require('axios');
  const chain = [];
  let url = `https://${target}`;
  
  try {
    for (let i = 0; i < 10; i++) {
      const response = await axios.get(url, { 
        timeout: 10000,
        maxRedirects: 0,
        validateStatus: () => true
      });
      
      chain.push({
        url,
        status: response.status,
        redirected: response.request?.res?.responseUrl || null
      });
      
      if (response.status >= 300 && response.status < 400) {
        url = response.headers.location;
        if (!url.startsWith('http')) {
          const urlObj = new URL(url, `https://${target}`);
          url = urlObj.toString();
        }
      } else {
        break;
      }
    }
    
    return { chain, count: chain.length };
  } catch (err) {
    return { chain: [], count: 0, error: err.message };
  }
}

/**
 * Check IP reputation
 */
async function checkReputation(target) {
  const geoip = require('./geoip');
  const blacklist = require('./blacklist-checker');
  
  try {
    const geo = await geoip.lookup(target);
    const bl = await blacklist.check(target);
    
    return {
      geo,
      blacklist: bl,
      hosting: geo.hosting || false,
      risk: bl.listed ? 'high' : (geo.hosting ? 'medium' : 'low')
    };
  } catch (err) {
    return { error: err.message };
  }
}

/**
 * Calculate security grade based on findings
 */
function calculateGrade(summary) {
  const score = summary.critical * 5 + summary.high * 3 + summary.medium * 1;
  
  if (summary.critical > 0) return 'F';
  if (summary.high > 3) return 'F';
  if (summary.high > 0) return 'D';
  if (summary.medium > 5) return 'C';
  if (summary.medium > 0) return 'B';
  return 'A';
}

/**
 * Get scan result by ID
 */
function getScanResult(scanId) {
  return scans.get(scanId) || null;
}

/**
 * Get scan history for a user
 */
function getScanHistory(userId) {
  return Array.from(scans.values())
    .filter(s => s.userId === userId)
    .map(s => ({
      id: s.id,
      target: s.target,
      status: s.status,
      progress: s.progress,
      summary: s.summary,
      startedAt: s.startedAt,
      completedAt: s.completedAt
    }))
    .sort((a, b) => new Date(b.startedAt) - new Date(a.startedAt));
}

/**
 * Delete a scan
 */
function deleteScan(scanId) {
  return scans.delete(scanId);
}

module.exports = {
  startScan,
  getScanResult,
  getScanHistory,
  deleteScan
};