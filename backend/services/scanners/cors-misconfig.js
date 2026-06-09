/**
 * CORS Misconfiguration Scanner
 * Detects Cross-Origin Resource Sharing vulnerabilities
 */

const axios = require('axios');

// Test origins to send
const TEST_ORIGINS = [
  'https://evil.com',
  'http://evil.com',
  'null',
  'https://attacker.com',
  'null',
  'https://example.com'
];

// Common vulnerable parameters
const VULNERABLE_PARAMS = [
  'origin', 'referer', 'x-origin', 'cors-origin', 'allow-origin'
];

/**
 * Check CORS headers in response
 */
function analyzeCORSHeaders(responseHeaders, testOrigin) {
  const headers = {};
  
  // Normalize headers to lowercase
  for (const [key, value] of Object.entries(responseHeaders)) {
    headers[key.toLowerCase()] = value;
  }

  const results = {
   ACAO: headers['access-control-allow-origin'],
    ACAC: headers['access-control-allow-credentials'],
    ACAM: headers['access-control-allow-methods'],
    ACAH: headers['access-control-allow-headers'],
    ACMA: headers['access-control-max-age']
  };

  // Check for misconfigurations
  const issues = [];

  // 1. Wildcard (*) in Access-Control-Allow-Origin
  if (results.ACAO === '*') {
    issues.push({
      type: 'wildcard-origin',
      severity: 'high',
      description: 'Access-Control-Allow-Origin is set to "*" (wildcard)',
      allowedOrigin: '*'
    });
  }

  // 2. Null origin allowed
  if (results.ACAO === 'null' || results.ACAO?.includes('null')) {
    issues.push({
      type: 'null-origin-allowed',
      severity: 'medium',
      description: 'Null origin is allowed in Access-Control-Allow-Origin',
      allowedOrigin: 'null'
    });
  }

  // 3. Credentials with wildcard
  if (results.ACAO === '*' && results.ACAC?.toLowerCase() === 'true') {
    issues.push({
      type: 'wildcard-with-credentials',
      severity: 'critical',
      description: 'Wildcard origin combined with credentials=true is insecure',
      allowedOrigin: '*'
    });
  }

  // 4. Any origin allowed with credentials
  if (results.ACAC?.toLowerCase() === 'true') {
    // Check if any origin is allowed (contains http or is just *)
    if (results.ACAO?.includes('http') || results.ACAO === '*') {
      issues.push({
        type: 'credentials-with-any-origin',
        severity: 'high',
        description: 'Credentials allowed with broad origin access',
        allowedOrigin: results.ACAO
      });
    }
  }

  // 5. Origin is reflected without validation
  if (results.ACAO && (results.ACAO === testOrigin || results.ACAO?.includes(testOrigin))) {
    // This is actually OK if it's just reflecting the origin
    // But we need to check if ANY origin is allowed
  }

  // 6. Check for multiple origins allowed (comma-separated or regex)
  if (results.ACAO && (results.ACAO.includes(',') || results.ACAO.includes(' '))) {
    issues.push({
      type: 'multiple-origins-allowed',
      severity: 'medium',
      description: 'Multiple origins appear to be allowed',
      allowedOrigin: results.ACAO
    });
  }

  // 7. Check for regex pattern in origin (might allow bypass)
  if (results.ACAO && (results.ACAO.includes('.*') || results.ACAO.includes('(') || results.ACAO.includes('|'))) {
    issues.push({
      type: 'regex-origin-pattern',
      severity: 'high',
      description: 'Regular expression pattern detected in origin header - possible bypass',
      allowedOrigin: results.ACAO
    });
  }

  return {
    issues,
    headers: results,
    hasMisconfig: issues.length > 0
  };
}

/**
 * Test CORS with a specific origin
 */
async function testOrigin(url, testOrigin) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    const response = await axios({
      method: 'GET',
      url,
      headers: {
        'Origin': testOrigin,
        'Access-Control-Request-Method': 'GET',
        'Access-Control-Request-Headers': 'X-Requested-With'
      },
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const analysis = analyzeCORSHeaders(response.headers, testOrigin);
    
    return {
      testOrigin,
      statusCode: response.status,
      ...analysis
    };

  } catch (error) {
    clearTimeout(timeout);
    return {
      testOrigin,
      error: error.message,
      issues: [],
      hasMisconfig: false
    };
  }
}

/**
 * Test for preflight bypass
 */
async function testPreflightBypass(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    // Send preflight OPTIONS request
    const response = await axios({
      method: 'OPTIONS',
      url,
      headers: {
        'Origin': 'https://evil.com',
        'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': 'Content-Type, X-Custom-Header'
      },
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const analysis = analyzeCORSHeaders(response.headers, 'https://evil.com');
    
    if (analysis.hasMisconfig) {
      return {
        vulnerable: true,
        type: 'preflight-bypass',
        issues: analysis.issues,
        evidence: 'Preflight request allowed sensitive headers'
      };
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test for origin reflection without validation
 */
async function testOriginReflection(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    // Send request with random origin
    const randomOrigin = 'https://' + Math.random().toString(36).substring(7) + '.com';
    
    const response = await axios({
      method: 'GET',
      url,
      headers: {
        'Origin': randomOrigin
      },
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const acao = response.headers['access-control-allow-origin'];
    
    // If the origin is reflected, it's not secure
    if (acao === randomOrigin) {
      return {
        vulnerable: true,
        type: 'origin-reflection',
        misconfigType: 'unvalidated-origin-reflection',
        allowedOrigin: acao,
        confidence: 'high',
        description: 'Origin is reflected without validation - attacker can set any origin'
      };
    }

    return { vulnerable: false, reflected: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Main scan function
 */
async function scan(target) {
  const { url } = target;

  const results = {
    vulnerable: false,
    misconfigurations: [],
    testedOrigins: 0
  };

  // Test with various origins
  for (const testOrigin of TEST_ORIGINS) {
    const testResult = await testOrigin(url, testOrigin);
    results.testedOrigins++;

    if (testResult.hasMisconfig) {
      results.vulnerable = true;
      results.misconfigurations.push(...testResult.issues);
    }
  }

  // Test for origin reflection
  const reflectionResult = await testOriginReflection(url);
  if (reflectionResult.vulnerable) {
    results.vulnerable = true;
    results.misconfigurations.push({
      type: reflectionResult.type,
      severity: 'high',
      description: reflectionResult.description,
      allowedOrigin: reflectionResult.allowedOrigin
    });
  }

  // Test preflight bypass
  const preflightResult = await testPreflightBypass(url);
  if (preflightResult.vulnerable) {
    results.vulnerable = true;
    results.misconfigurations.push(...preflightResult.issues);
  }

  return {
    success: true,
    ...results
  };
}

module.exports = { scan };