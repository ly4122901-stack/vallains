/**
 * SSRF Scanner
 * Detects Server-Side Request Forgery vulnerabilities
 */

const axios = require('axios');

// Internal targets to test
const INTERNAL_TARGETS = [
  // AWS Metadata
  'http://169.254.169.254/latest/meta-data/',
  'http://169.254.169.254/latest/user-data/',
  'http://169.254.169.254/latest/meta-data/instance-id',
  'http://169.254.169.254/latest/meta-data/iam/security-credentials/',
  
  // Localhost variations
  'http://localhost/',
  'http://127.0.0.1/',
  'http://127.0.0.1:80/',
  'http://[::1]/',
  'http://[::1]:80/',
  
  // All zeros
  'http://0.0.0.0/',
  'http://0.0.0.0:80/',
  
  // Internal network ranges
  'http://10.0.0.1/',
  'http://10.255.255.255/',
  'http://172.16.0.1/',
  'http://172.31.255.255/',
  'http://192.168.0.1/',
  'http://192.168.255.255/'
];

// Common SSRF vulnerable parameters
const SSRF_PARAMS = [
  'url', 'uri', 'src', 'source', 'link', 'href', 'redirect', 'path',
  'dest', 'destination', 'next', 'data', 'reference', 'site', 'html',
  'val', 'validate', 'domain', 'callback', 'return', 'page', 'feed',
  'host', 'port', 'to', 'out', 'view', 'dir', 'action', 'encode',
  'type', 'file', 'name', 'cmd', 'tel', 'template', 'id', 'doc',
  'debug', 'reg', 'cap', 'realpath', 'ds', 'param', 'do', 'func'
];

// Patterns that indicate successful internal resource access
const INTERNAL_PATTERNS = [
  // AWS patterns
  /ami-id/i,
  /instance-id/i,
  /instance-type/i,
  /aws-access-key/i,
  /iam\/security-credentials/i,
  /mac-address/i,
  
  // Localhost patterns
  /localhost/i,
  /127\.0\.0\.1/i,
  /::1/i,
  
  // File system patterns
  /root:x:/i,
  /bin\/bash/i,
  /\[boot loader\]/i,
  /boot\.ini/i,
  
  // Generic patterns
  /<!DOCTYPE/i,
  /<html/i,
  /<!\[CDATA/i,
  /\{\"ami/i
];

// Error patterns that indicate SSRF might be possible
const SSRF_ERROR_PATTERNS = [
  /Connection refused/i,
  /Connection timed out/i,
  /No route to host/i,
  /Network is unreachable/i,
  /Timeout/i,
  /ECONNREFUSED/i,
  /ETIMEDOUT/i,
  /ENETUNREACH/i,
  /socket hang up/i,
  /Request timeout/i,
  /fetch failed/i,
  /Failed to fetch/i,
  /cURL error/i,
  /GuzzleHTTP/i,
  /cannot resolve/i,
  /No such host/i
];

/**
 * Test SSRF with a specific internal target
 */
async function testInternalTarget(url, method, paramName, paramValue, internalTarget) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    let testUrl = url;
    let testBody = null;

    const modifiedPayload = paramValue + internalTarget;

    if (method === 'GET') {
      const urlObj = new URL(url);
      urlObj.searchParams.set(paramName, modifiedPayload);
      testUrl = urlObj.toString();
    } else {
      testBody = { [paramName]: modifiedPayload };
    }

    const response = await axios({
      method,
      url: testUrl,
      data: testBody,
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for internal resource patterns
    for (const pattern of INTERNAL_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload: internalTarget,
          internalResourceFound: true,
          type: 'internal-fetch',
          parameter: paramName,
          confidence: 'high',
          evidence: responseText.substring(0, 500)
        };
      }
    }

    // Check response time as indicator (slow response might mean internal fetch)
    // This is heuristic and not reliable

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    
    // Check if error suggests SSRF possibility
    const errorText = error.message || '';
    for (const pattern of SSRF_ERROR_PATTERNS) {
      if (pattern.test(errorText)) {
        // This might indicate the server tried to fetch internal resource
        return {
          vulnerable: true,
          payload: internalTarget,
          internalResourceFound: false,
          type: 'potential-ssrf',
          parameter: paramName,
          confidence: 'medium',
          evidence: errorText
        };
      }
    }
    
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test for blind SSRF via time-based detection
 */
async function testBlindSSRF(url, method, paramName, paramValue, internalTarget) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 15000); // Longer timeout for time-based

  try {
    const startTime = Date.now();
    
    let testUrl = url;
    let testBody = null;

    if (method === 'GET') {
      const urlObj = new URL(url);
      urlObj.searchParams.set(paramName, paramValue + internalTarget);
      testUrl = urlObj.toString();
    } else {
      testBody = { [paramName]: paramValue + internalTarget };
    }

    const response = await axios({
      method,
      url: testUrl,
      data: testBody,
      timeout: 15000,
      signal: controller.signal,
      validateStatus: () => true
    });

    const duration = Date.now() - startTime;
    clearTimeout(timeout);

    // If response takes longer than 5 seconds, might indicate SSRF
    if (duration > 5000) {
      return {
        vulnerable: true,
        payload: internalTarget,
        internalResourceFound: false,
        type: 'time-based-blind-ssrf',
        parameter: paramName,
        confidence: 'medium',
        evidence: `Response time: ${duration}ms`
      };
    }

    return { vulnerable: false, duration };

  } catch (error) {
    clearTimeout(timeout);
    
    // Timeout might indicate the server is trying to reach internal resource
    if (error.code === 'ETIMEDOUT' || error.code === 'ECONNREFUSED') {
      return {
        vulnerable: true,
        payload: internalTarget,
        internalResourceFound: false,
        type: 'potential-ssrf',
        parameter: paramName,
        confidence: 'low',
        evidence: error.message
      };
    }
    
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Main scan function
 */
async function scan(target) {
  const { url, params, method = 'GET' } = target;

  const results = {
    vulnerable: false,
    vulnerabilities: [],
    tested: { params: 0, internalTargets: 0 }
  };

  // Find parameters to test
  const paramsToTest = Object.keys(params).length > 0
    ? Object.keys(params)
    : SSRF_PARAMS;

  // Test each parameter
  for (const paramName of paramsToTest) {
    const paramValue = params[paramName] || '';
    results.tested.params++;

    for (const internalTarget of INTERNAL_TARGETS) {
      results.tested.internalTargets++;

      const result = await testInternalTarget(url, method, paramName, paramValue, internalTarget);

      if (result.vulnerable) {
        results.vulnerable = true;
        results.vulnerabilities.push(result);

        // Return first high confidence finding
        if (result.confidence === 'high') {
          return {
            success: true,
            ...results
          };
        }
      }
    }
  }

  return {
    success: true,
    ...results
  };
}

module.exports = { scan };