/**
 * DNS Resolver
 * Resolves domain names to various DNS record types
 */

const dns = require('dns');
const axios = require('axios');

// DNS-over-HTTPS endpoint
const DOH_ENDPOINT = 'https://dns.google/resolve';

// Promise-based DNS lookup wrapper
function dnsResolve(hostname, recordType) {
  return new Promise((resolve, reject) => {
    const options = {
      timeout: 10000,
      tries: 2
    };

    switch (recordType) {
      case 'A':
        dns.resolve4(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'AAAA':
        dns.resolve6(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'MX':
        dns.resolveMx(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'NS':
        dns.resolveNs(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'TXT':
        dns.resolveTxt(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'CNAME':
        dns.resolveCname(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      case 'PTR':
        dns.reverse(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
        break;
      
      default:
        // Try A record for unknown types
        dns.resolve4(hostname, options, (err, addresses) => {
          if (err) reject(err);
          else resolve(addresses || []);
        });
    }
  });
}

/**
 * Resolve using DNS-over-HTTPS (fallback)
 */
async function resolveViaDOH(domain, recordType) {
  const typeMap = {
    'A': 1,
    'AAAA': 28,
    'MX': 15,
    'NS': 2,
    'TXT': 16,
    'CNAME': 5,
    'PTR': 12
  };

  const queryType = typeMap[recordType] || 1;

  try {
    const response = await axios.get(DOH_ENDPOINT, {
      params: {
        name: domain,
        type: queryType
      },
      timeout: 10000
    });

    if (response.data.Status === 0 && response.data.Answer) {
      return response.data.Answer.map(answer => {
        if (recordType === 'MX') {
          return { priority: answer.PRIORITY, exchange: answer.data };
        }
        return answer.data;
      });
    }

    return [];
  } catch (error) {
    return [];
  }
}

/**
 * Resolve a domain to all record types
 */
async function resolveDomain(domain) {
  const results = {
    domain,
    success: true,
    timestamp: new Date().toISOString(),
    ipv4: [],
    ipv6: [],
    mx: [],
    ns: [],
    txt: [],
    cname: [],
    errors: []
  };

  // Clean domain
  let cleanDomain = domain.replace(/^https?:\/\//, '');
  cleanDomain = cleanDomain.split('/')[0];
  cleanDomain = cleanDomain.split(':')[0];

  try {
    // Resolve A records
    try {
      results.ipv4 = await dnsResolve(cleanDomain, 'A');
    } catch (e) {
      results.errors.push({ type: 'A', error: e.message });
      // Try DOH fallback
      const fallback = await resolveViaDOH(cleanDomain, 'A');
      results.ipv4 = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'A', error: e.message });
  }

  try {
    // Resolve AAAA records
    try {
      results.ipv6 = await dnsResolve(cleanDomain, 'AAAA');
    } catch (e) {
      results.errors.push({ type: 'AAAA', error: e.message });
      // Try DOH fallback
      const fallback = await resolveViaDOH(cleanDomain, 'AAAA');
      results.ipv6 = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'AAAA', error: e.message });
  }

  try {
    // Resolve MX records
    try {
      results.mx = await dnsResolve(cleanDomain, 'MX');
    } catch (e) {
      results.errors.push({ type: 'MX', error: e.message });
      const fallback = await resolveViaDOH(cleanDomain, 'MX');
      results.mx = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'MX', error: e.message });
  }

  try {
    // Resolve NS records
    try {
      results.ns = await dnsResolve(cleanDomain, 'NS');
    } catch (e) {
      results.errors.push({ type: 'NS', error: e.message });
      const fallback = await resolveViaDOH(cleanDomain, 'NS');
      results.ns = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'NS', error: e.message });
  }

  try {
    // Resolve TXT records
    try {
      const txtRecords = await dnsResolve(cleanDomain, 'TXT');
      results.txt = txtRecords.flat(); // Flatten as TXT can have multiple strings
    } catch (e) {
      results.errors.push({ type: 'TXT', error: e.message });
      const fallback = await resolveViaDOH(cleanDomain, 'TXT');
      results.txt = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'TXT', error: e.message });
  }

  try {
    // Resolve CNAME records
    try {
      results.cname = await dnsResolve(cleanDomain, 'CNAME');
    } catch (e) {
      results.errors.push({ type: 'CNAME', error: e.message });
      const fallback = await resolveViaDOH(cleanDomain, 'CNAME');
      results.cname = fallback;
    }
  } catch (e) {
    results.errors.push({ type: 'CNAME', error: e.message });
  }

  return results;
}

/**
 * Perform reverse DNS lookup
 */
async function reverseLookup(ip) {
  const results = {
    ip,
    success: true,
    timestamp: new Date().toISOString(),
    hostnames: [],
    error: null
  };

  try {
    const hostnames = await dnsResolve(ip, 'PTR');
    results.hostnames = hostnames;
  } catch (e) {
    results.error = e.message;
    results.hostnames = [];
  }

  return results;
}

/**
 * Lookup SPF record for domain
 */
async function getSPFRecord(domain) {
  try {
    const txtRecords = await dnsResolve(domain, 'TXT');
    for (const record of txtRecords) {
      if (record.toLowerCase().startsWith('v=spf1')) {
        return record;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Check for DMARC record
 */
async function getDMARCRecord(domain) {
  try {
    const dmarcDomain = '_dmarc.' + domain;
    const txtRecords = await dnsResolve(dmarcDomain, 'TXT');
    for (const record of txtRecords) {
      if (record.toLowerCase().startsWith('v=dmarc1')) {
        return record;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

/**
 * Check for DKIM record
 */
async function getDKIMRecord(domain, selector = 'default') {
  try {
    const dkimDomain = selector + '._domainkey.' + domain;
    const txtRecords = await dnsResolve(dkimDomain, 'TXT');
    for (const record of txtRecords) {
      if (record.toLowerCase().startsWith('v=dkim1')) {
        return record;
      }
    }
    return null;
  } catch (e) {
    return null;
  }
}

module.exports = {
  resolveDomain,
  reverseLookup,
  getSPFRecord,
  getDMARCRecord,
  getDKIMRecord,
  dnsResolve,
  resolveViaDOH
};