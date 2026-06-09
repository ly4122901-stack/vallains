const express = require('express');
const router = express.Router();
const { requireAuth, optionalAuth } = require('../middleware/auth');

// Import services
const scanEngine = require('../services/scan-engine');
const dnsResolver = require('../services/dns-resolver');
const geoip = require('../services/geoip');
const sslChecker = require('../services/ssl-checker');
const portScanner = require('../services/port-scanner');
const subdomainFinder = require('../services/subdomain-finder');
const blacklistChecker = require('../services/blacklist-checker');

// Health check (public)
router.get('/health', (req, res) => {
  res.json({
    success: true,
    status: 'healthy',
    timestamp: new Date().toISOString()
  });
});

// Start a new scan (requires auth)
router.post('/scan', requireAuth, async (req, res) => {
  try {
    const { target, options } = req.body;
    
    if (!target) {
      return res.status(400).json({
        success: false,
        error: 'Target is required'
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

// Get scan status/results (requires auth)
router.get('/scan/:scanId', requireAuth, async (req, res) => {
  try {
    const result = await scanEngine.getScanResult(req.params.scanId);
    
    if (!result) {
      return res.status(404).json({
        success: false,
        error: 'Scan not found'
      });
    }

    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Get scan history (requires auth)
router.get('/scans', requireAuth, async (req, res) => {
  try {
    const history = scanEngine.getScanHistory(req.user.id);
    res.json({
      success: true,
      scans: history
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// DNS Lookup (optional auth for rate limiting)
router.post('/dns/lookup', optionalAuth, async (req, res) => {
  try {
    const { domain } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
      });
    }

    const result = await dnsResolver.lookup(domain);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// GeoIP Lookup (optional auth)
router.get('/geoip/:ip', optionalAuth, async (req, res) => {
  try {
    const result = await geoip.lookup(req.params.ip);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// SSL Certificate Check (optional auth)
router.post('/ssl/check', optionalAuth, async (req, res) => {
  try {
    const { host, port } = req.body;
    
    if (!host) {
      return res.status(400).json({
        success: false,
        error: 'Host is required'
      });
    }

    const result = await sslChecker.check(host, port || 443);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Port Scan (optional auth)
router.post('/ports/scan', optionalAuth, async (req, res) => {
  try {
    const { host, ports, timeout } = req.body;
    
    if (!host) {
      return res.status(400).json({
        success: false,
        error: 'Host is required'
      });
    }

    const io = req.app.get('io');
    const result = await portScanner.scan(host, ports, timeout, io);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Subdomain Finder (optional auth)
router.post('/subdomains', optionalAuth, async (req, res) => {
  try {
    const { domain, wordlist } = req.body;
    
    if (!domain) {
      return res.status(400).json({
        success: false,
        error: 'Domain is required'
      });
    }

    const io = req.app.get('io');
    const result = await subdomainFinder.find(domain, wordlist, io);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

// Blacklist Check (optional auth)
router.post('/blacklist/check', optionalAuth, async (req, res) => {
  try {
    const { domain, ip } = req.body;
    
    if (!domain && !ip) {
      return res.status(400).json({
        success: false,
        error: 'Domain or IP is required'
      });
    }

    const result = await blacklistChecker.check(domain, ip);
    res.json({
      success: true,
      ...result
    });
  } catch (err) {
    res.status(500).json({
      success: false,
      error: err.message
    });
  }
});

module.exports = router;