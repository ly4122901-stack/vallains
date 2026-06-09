const dns = require('dns');
const { promisify } = require('util');

const resolve4 = promisify(dns.resolve4);
const resolve6 = promisify(dns.resolve6);

// Common subdomains to check
const DEFAULT_WORDLIST = [
  'www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'staging',
  'api', 'cdn', 'static', 'assets', 'images', 'img', 'video',
  'smtp', 'pop', 'imap', 'ssh', 'vpn', 'gitlab', 'jenkins',
  'jira', 'confluence', 'docs', 'documentation', 'help',
  'shop', 'store', 'cart', 'checkout', 'pay', 'payment',
  'secure', 'login', 'auth', 'sso', 'oauth', 'register',
  'status', 'monitor', 'metrics', 'grafana', 'kibana',
  'db', 'database', 'mysql', 'postgres', 'mongo', 'redis',
  'backup', 'backups', 'archive', 'old', 'beta', 'alpha',
  'demo', 'sandbox', 'lab', 'research', 'internal'
];

// DNS record types to check
const RECORD_TYPES = ['A', 'AAAA', 'CNAME'];

/**
 * Check if a subdomain exists
 */
async function checkSubdomain(domain, subdomain) {
  const fullDomain = `${subdomain}.${domain}`;
  
  try {
    const results = {};
    
    for (const type of RECORD_TYPES) {
      try {
        const resolver = type === 'A' ? resolve4 : 
                        type === 'AAAA' ? resolve6 : 
                        dns.resolve;
        const records = await resolver(fullDomain);
        results[type] = records;
      } catch (e) {
        results[type] = [];
      }
    }

    const hasRecords = Object.values(results).some(arr => arr.length > 0);
    
    return {
      subdomain: fullDomain,
      exists: hasRecords,
      records: results
    };
  } catch (err) {
    return {
      subdomain: fullDomain,
      exists: false,
      records: {},
      error: err.message
    };
  }
}

/**
 * Find subdomains
 * @param {string} domain - Target domain
 * @param {string[]} wordlist - Array of subdomains to check
 * @param {object} io - Socket.io instance
 */
async function find(domain, wordlist = null, io) {
  const subdomains = wordlist || DEFAULT_WORDLIST;
  
  const result = {
    domain,
    timestamp: new Date().toISOString(),
    found: [],
    notFound: 0,
    totalChecked: subdomains.length,
    success: false
  };

  const batchSize = 10;
  
  for (let i = 0; i < subdomains.length; i += batchSize) {
    const batch = subdomains.slice(i, i + batchSize);
    
    const batchResults = await Promise.all(
      batch.map(sub => checkSubdomain(domain, sub))
    );

    for (const check of batchResults) {
      if (check.exists) {
        result.found.push({
          subdomain: check.subdomain,
          records: check.records
        });
      } else {
        result.notFound++;
      }
    }

    // Emit progress
    if (io) {
      io.emit('scan:progress', {
        step: 'subdomains',
        progress: Math.round(((i + batch.length) / subdomains.length) * 100),
        found: result.found.length
      });
    }
  }

  result.success = true;
  return result;
}

/**
 * Bruteforce subdomains with custom wordlist
 */
async function bruteforce(domain, wordlistPath) {
  // For production, read wordlist from file
  // For now, return empty array
  return [];
}

module.exports = {
  find,
  checkSubdomain,
  DEFAULT_WORDLIST
};