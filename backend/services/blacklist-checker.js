const dns = require('dns');
const { promisify } = require('util');

const resolveTxt = promisify(dns.resolveTxt);

// Major blacklist DNS zones
const BLACKLISTS = [
  { name: 'Spamhaus DBL', zone: 'dbl.spamhaus.org', type: 'domain' },
  { name: 'Spamhaus SBL', zone: 'sbl.spamhaus.org', type: 'ip' },
  { name: 'Spamhaus XBL', zone: 'xbl.spamhaus.org', type: 'ip' },
  { name: 'Spamhaus PBL', zone: 'pbl.spamhaus.org', type: 'ip' },
  { name: 'SURBL', zone: 'multi.surbl.org', type: 'domain' },
  { name: 'URIBL', zone: 'uribl.spameatingmonkey.net', type: 'domain' },
  { name: 'DNSBL Score', zone: 'dnsbl.sorbs.net', type: 'ip' },
  { name: 'DNSBL AHBL', zone: 'dnsbl.ahbl.org', type: 'ip' },
  { name: 'NJABL', zone: 'dnsbl.njabl.org', type: 'ip' },
  { name: 'PSBL', zone: 'psbl.surriel.com', type: 'ip' }
];

/**
 * Reverse IP address for DNSBL lookup
 */
function reverseIP(ip) {
  return ip.split('.').reverse().join('.');
}

/**
 * Extract domain from hostname
 */
function extractDomain(hostname) {
  // Remove protocol if present
  hostname = hostname.replace(/^(https?:\/\/)?/, '');
  // Remove path if present
  hostname = hostname.split('/')[0];
  // Remove www. prefix
  hostname = hostname.replace(/^www\./, '');
  return hostname;
}

/**
 * Check a single blacklist
 */
async function checkBlacklist(target, blacklist) {
  let queryDomain;
  
  if (blacklist.type === 'ip') {
    queryDomain = `${reverseIP(target)}.${blacklist.zone}`;
  } else {
    queryDomain = `${target}.${blacklist.zone}`;
  }

  try {
    const records = await resolveTxt(queryDomain);
    return {
      blacklist: blacklist.name,
      listed: true,
      reason: records[0]?.[0] || 'Found in blacklist'
    };
  } catch (err) {
    if (err.code === 'ENOTFOUND') {
      return {
        blacklist: blacklist.name,
        listed: false,
        reason: null
      };
    }
    return {
      blacklist: blacklist.name,
      listed: null,
      reason: 'DNS lookup failed'
    };
  }
}

/**
 * Check domain or IP against blacklists
 * @param {string} domain - Target domain
 * @param {string} ip - Target IP (optional)
 */
async function check(domain = null, ip = null) {
  const result = {
    timestamp: new Date().toISOString(),
    checks: [],
    listedOn: [],
    clean: true,
    success: false
  };

  // Determine target
  let target = ip;
  let targetType = 'ip';
  
  if (domain && !ip) {
    target = extractDomain(domain);
    targetType = 'domain';
  }

  if (!target) {
    result.error = 'No valid domain or IP provided';
    return result;
  }

  result.target = target;
  result.targetType = targetType;

  // Filter relevant blacklists
  const relevantBlacklists = BLACKLISTS.filter(bl => 
    bl.type === targetType || targetType === 'ip'
  );

  // Check all blacklists
  for (const blacklist of relevantBlacklists) {
    const checkResult = await checkBlacklist(target, blacklist);
    result.checks.push(checkResult);
    
    if (checkResult.listed === true) {
      result.listedOn.push(checkResult);
      result.clean = false;
    }
  }

  result.success = true;
  result.totalChecks = result.checks.length;
  result.listedCount = result.listedOn.length;
  
  return result;
}

/**
 * Quick blacklist check for common blacklists
 */
async function quickCheck(ip) {
  const criticalBlacklists = BLACKLISTS.slice(0, 3);
  
  const result = {
    ip,
    timestamp: new Date().toISOString(),
    checks: [],
    clean: true
  };

  for (const blacklist of criticalBlacklists) {
    const checkResult = await checkBlacklist(ip, blacklist);
    result.checks.push(checkResult);
    
    if (checkResult.listed) {
      result.clean = false;
    }
  }

  return result;
}

module.exports = {
  check,
  quickCheck,
  reverseIP,
  BLACKLISTS
};