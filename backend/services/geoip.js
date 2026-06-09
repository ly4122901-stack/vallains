/**
 * GeoIP Lookup
 * Provides geographic and network information for IP addresses
 */

const dns = require('dns');
const axios = require('axios');

// Free GeoIP API endpoints
const GEO_ENDPOINTS = [
  'https://ip-api.com/json/',
  'https://ipapi.co/json/',
  'https://ipinfo.io/json'
];

// Cache for repeated lookups
const cache = new Map();
const CACHE_TTL = 3600000; // 1 hour

/**
 * Validate IP address
 */
function isValidIP(ip) {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6 (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  
  if (ipv4Regex.test(ip)) {
    const parts = ip.split('.');
    return parts.every(part => {
      const num = parseInt(part, 10);
      return num >= 0 && num <= 255;
    });
  }
  
  return ipv6Regex.test(ip);
}

/**
 * Resolve domain to IP first
 */
async function resolveDomainToIP(domain) {
  return new Promise((resolve, reject) => {
    dns.resolve4(domain, (err, addresses) => {
      if (err || !addresses || addresses.length === 0) {
        dns.resolve6(domain, (err6, addresses6) => {
          if (err6 || !addresses6 || addresses6.length === 0) {
            reject(new Error('Could not resolve domain to IP'));
          } else {
            resolve(addresses6[0]);
          }
        });
      } else {
        resolve(addresses[0]);
      }
    });
  });
}

/**
 * Get from cache or fetch fresh data
 */
async function getWithCache(ip, fetcher) {
  const cached = cache.get(ip);
  if (cached && (Date.now() - cached.timestamp) < CACHE_TTL) {
    return cached.data;
  }

  const data = await fetcher();
  cache.set(ip, { data, timestamp: Date.now() });
  return data;
}

/**
 * Fetch from ip-api.com
 */
async function fetchFromIpApi(ip) {
  try {
    const response = await axios.get(`${GEO_ENDPOINTS[0]}${ip}`, {
      timeout: 5000
    });

    if (response.data.status === 'success') {
      return {
        country: response.data.country || null,
        countryCode: response.data.countryCode || null,
        city: response.data.city || null,
        region: response.data.regionName || null,
        regionCode: response.data.region || null,
        lat: response.data.lat || null,
        lon: response.data.lon || null,
        timezone: response.data.timezone || null,
        isp: response.data.isp || null,
        org: response.data.org || null,
        asn: response.data.as || null,
        hosting: response.data.hosting || false,
        query: response.data.query || ip
      };
    }
    throw new Error('API returned failure status');
  } catch (e) {
    return null;
  }
}

/**
 * Fetch from ipapi.co
 */
async function fetchFromIpApiCo(ip) {
  try {
    const response = await axios.get(`${GEO_ENDPOINTS[1]}${ip}`, {
      timeout: 5000
    });

    if (response.data && !response.data.error) {
      return {
        country: response.data.country_name || null,
        countryCode: response.data.country_code || null,
        city: response.data.city || null,
        region: response.data.region || null,
        regionCode: response.data.region_code || null,
        lat: response.data.latitude || null,
        lon: response.data.longitude || null,
        timezone: response.data.timezone || null,
        isp: response.data.org || null,
        org: response.data.org || null,
        asn: response.data.asn || null,
        hosting: response.data.country_code !== response.data.country ? true : false,
        query: ip
      };
    }
    throw new Error('API returned error');
  } catch (e) {
    return null;
  }
}

/**
 * Fetch from ipinfo.io
 */
async function fetchFromIpInfo(ip) {
  try {
    const response = await axios.get(`${GEO_ENDPOINTS[2]}`, {
      params: { ip },
      timeout: 5000
    });

    if (response.data && response.data.ip) {
      const loc = response.data.loc ? response.data.loc.split(',') : [];
      return {
        country: response.data.country || null,
        countryCode: response.data.country || null,
        city: response.data.city || null,
        region: response.data.region || null,
        regionCode: null,
        lat: loc[0] ? parseFloat(loc[0]) : null,
        lon: loc[1] ? parseFloat(loc[1]) : null,
        timezone: response.data.timezone || null,
        isp: response.data.org || null,
        org: response.data.org || null,
        asn: response.data.asn || null,
        hosting: false,
        query: ip
      };
    }
    throw new Error('API returned invalid data');
  } catch (e) {
    return null;
  }
}

/**
 * Main GeoIP lookup function
 */
async function getGeoIP(target) {
  let ip = target;
  
  // If target is a domain, resolve to IP
  if (!isValidIP(target)) {
    try {
      ip = await resolveDomainToIP(target);
    } catch (e) {
      return {
        success: false,
        error: 'Could not resolve domain to IP address',
        target
      };
    }
  }

  try {
    // Try first endpoint
    let result = await fetchFromIpApi(ip);
    
    if (!result) {
      // Try second endpoint
      result = await fetchFromIpApiCo(ip);
    }
    
    if (!result) {
      // Try third endpoint
      result = await fetchFromIpInfo(ip);
    }

    if (result) {
      return {
        success: true,
        ip,
        ...result
      };
    }

    // All APIs failed
    return {
      success: false,
      error: 'All GeoIP services failed',
      ip
    };

  } catch (error) {
    return {
      success: false,
      error: error.message,
      ip
    };
  }
}

/**
 * Batch lookup for multiple IPs
 */
async function batchGeoIP(ips) {
  const results = await Promise.all(
    ips.map(ip => getGeoIP(ip).catch(err => ({ success: false, ip, error: err.message })))
  );
  return results;
}

/**
 * Clear cache
 */
function clearCache() {
  cache.clear();
}

/**
 * Get cache stats
 */
function getCacheStats() {
  return {
    size: cache.size,
    entries: Array.from(cache.keys())
  };
}

module.exports = {
  getGeoIP,
  batchGeoIP,
  clearCache,
  getCacheStats,
  isValidIP
};