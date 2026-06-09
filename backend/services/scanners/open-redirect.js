/**
 * Open Redirect Scanner
 * Detects Open Redirect vulnerabilities
 */

const axios = require('axios');

// Common redirect parameters
const REDIRECT_PARAMS = [
  'redirect', 'url', 'next', 'dest', 'checkout', 'return', 'continue',
  'back', 'to', 'out', 'view', 'go', 'open', 'load', 'file', 'page',
  'reference', 'ref', 'src', 'source', 'target', 'uri', 'location',
  'callback', 'origin', 'redir', 'navigate', 'exit', 'from', 'domain'
];

// Open redirect payloads
const PAYLOADS = [
  // Absolute URL redirects
  'https://google.com',
  'https://evil.com',
  
  // Protocol-relative redirects
  '//google.com',
  '///google.com',
  
  // Null byte prefix (bypass some filters)
  '//google.com',
  '///google.com',
  
  // JavaScript protocol
  'javascript:alert(1)',
  'javascript:alert(document.cookie)',
  'JavaScript:alert(1)',
  
  // Data URI (sometimes works)
  'data:text/html,<script>alert(1)</script>',
  
  // Double encoding
  '%2F%2Fgoogle.com',
  '%252F%252Fgoogle.com',
  
  // Embedded newlines (bypass some filters)
  '//google.com%0A',
  '//google.com%E2%80%8A',
  
  // Unicode normalization
  '//google.com％EF％BC％8F',
  
  // Path traversal with redirect
  '../../../../../../../../../../../../../etc/passwd',
  '/../../../../../../../../../etc/passwd'
];

// Domains to check in Location header
const CHECK_DOMAINS = [
  'google.com', 'evil.com', 'example.com', 'test.com'
];

/**
 * Check if response redirects to external domain
 */
function checkRedirect(response, payloadDomain) {
  const location = response.headers['location'];
  const refresh = response.headers['refresh'];
  
  if (location) {
    // Check if redirecting to external domain
    try {
      const redirectUrl = new URL(location);
      if (redirectUrl.hostname !== 'localhost' && 
          redirectUrl.hostname !== '127.0.0.1' &&
          !redirectUrl.hostname.includes('localhost')) {
        return {
          redirected: true,
          redirectTo: location,
          isExternal: true,
          method: 'location'
        };
      }
    } catch (e) {
      // Relative URL - might be internal
      return {
        redirected: true,
        redirectTo: location,
        isExternal: false,
        method: 'location'
      };
    }
  }
  
  if (refresh) {
    const match = refresh.match(/url=['"]?([^;'"]+)/i);
    if (match) {
      return {
        redirected: true,
        redirectTo: match[1],
        isExternal: true,
        method: 'refresh'
      };
    }
  }
  
  return { redirected: false };
}

/**
 * Test a single parameter with payload
 */
async function testParameter(url, method, paramName, paramValue, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    let testUrl = url;
    let testBody = null;

    const modifiedPayload = paramValue + payload;

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
      validateStatus: () => true,
      maxRedirects: 0, // Don't follow redirects
      // Allow redirect to external domains for testing
      validateStatus: (status) => status >= 200 && status < 400
    });

    clearTimeout(timeout);

    const redirectCheck = checkRedirect(response, 'google.com');
    
    if (redirectCheck.redirected && redirectCheck.isExternal) {
      return {
        vulnerable: true,
        payload,
        redirectTo: redirectCheck.redirectTo,
        type: 'unvalidated-redirect',
        location: method === 'GET' ? 'query' : 'body',
        parameter: paramName,
        confidence: 'high',
        evidence: `Redirects to: ${redirectCheck.redirectTo}`
      };
    }
    
    if (redirectCheck.redirected) {
      return {
        vulnerable: true,
        payload,
        redirectTo: redirectCheck.redirectTo,
        type: 'validated-redirect',
        location: method === 'GET' ? 'query' : 'body',
        parameter: paramName,
        confidence: 'medium',
        evidence: `Redirects to: ${redirectCheck.redirectTo}`
      };
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    
    // Check if error indicates redirect happened
    if (error.code === 'ERR_FR_REDIRECTION_NOT_FOLLOWED' || 
        error.message.includes('redirect')) {
      return {
        vulnerable: true,
        payload,
        type: 'redirect-detected',
        confidence: 'medium',
        evidence: error.message
      };
    }
    
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test for meta refresh redirects
 */
async function testMetaRefresh(url, paramName, paramValue, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const urlObj = new URL(url);
    urlObj.searchParams.set(paramName, paramValue + payload);
    
    const response = await axios({
      url: urlObj.toString(),
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for meta refresh tag with external URL
    const metaRefreshMatch = responseText.match(/<meta[^>]*refresh[^>]*content=["'][^"']*url=([^;"']+)/i);
    if (metaRefreshMatch) {
      const refreshUrl = metaRefreshMatch[1];
      if (refreshUrl.includes('://') && !refreshUrl.includes('localhost')) {
        return {
          vulnerable: true,
          payload,
          type: 'meta-refresh',
          parameter: paramName,
          confidence: 'high',
          evidence: `Meta refresh to: ${refreshUrl}`
        };
      }
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
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
    tested: { params: 0, payloads: 0 }
  };

  // Find parameters to test
  const paramsToTest = Object.keys(params).length > 0
    ? Object.keys(params)
    : REDIRECT_PARAMS;

  // Test each parameter
  for (const paramName of paramsToTest) {
    const paramValue = params[paramName] || '';
    results.tested.params++;

    for (const payload of PAYLOADS) {
      results.tested.payloads++;

      const result = await testParameter(url, method, paramName, paramValue, payload);

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